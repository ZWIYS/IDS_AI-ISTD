# =============================================================================
# attack-detection.R — скоринг, rule-based классификация, алерты
# =============================================================================

#' @keywords internal
.adaptive_min <- function(x, base, frac = DETECT_PARAMS$rules$adaptive_frac, floor_val = 2L) {
  m <- suppressWarnings(max(x, na.rm = TRUE))
  if (!is.finite(m) || m <= 0) return(as.numeric(floor_val))
  max(floor_val, min(base, ceiling(m * frac)))
}

#' @keywords internal
.ensure_rule_cols <- function(dt) {
  need <- c(
    "conn_count_5min", "dest_port_distinct", "unique_dst_ip",
    "duration", "orig_bytes", "resp_bytes",
    "query_entropy", "query_length", "uri_length", "http_status_code",
    "ssl_sni_entropy", "ssl_sni_length", "data_volume_change"
  )
  for (col in need) {
    if (col %in% names(dt)) next
    def <- FEATURE_DEFAULTS[[col]] %||% 0
    dt[, (col) := def]
  }
  dt
}

#' Rule-based классификация типа атаки
#'
#' @param dt Таблица с признаками.
#' @param rules Список порогов (по умолчанию `DETECT_PARAMS$rules`).
#' @return `data.table` с колонками `attack_score`, `attack_type`.
#' @export
classify_attacks <- function(dt, rules = DETECT_PARAMS$rules) {
  dt <- data.table::as.data.table(dt)
  dt <- .ensure_rule_cols(dt)
  dt[, attack_score := 1L]
  dt[, attack_type := rules$fallback_type %||% "ml_anomaly"]

  dt[conn_count_5min >= 500 & dest_port_distinct <= 5,
     `:=`(attack_score = 4L, attack_type = "ddos")]
  dt[conn_count_5min >= 100 & dest_port_distinct >= 50 & attack_type == rules$fallback_type,
     `:=`(attack_score = 3L, attack_type = "port_scan")]
  dt[conn_count_5min >= 300 & orig_bytes > 1e5 & resp_bytes < 1e3 & attack_type == rules$fallback_type,
     `:=`(attack_score = 3L, attack_type = "exfiltration")]
  dt[conn_count_5min >= 200 & unique_dst_ip >= 20 & attack_type == rules$fallback_type,
     `:=`(attack_score = 3L, attack_type = "botnet")]
  dt[conn_count_5min >= 400 & duration < 0.1 & attack_type == rules$fallback_type,
     `:=`(attack_score = 3L, attack_type = "dos")]

  thr_conn  <- .adaptive_min(dt$conn_count_5min, 500)
  thr_ports <- .adaptive_min(dt$dest_port_distinct, 50)
  thr_dst   <- .adaptive_min(dt$unique_dst_ip, 20)

  dt[conn_count_5min >= thr_conn & dest_port_distinct <= 3 & attack_type == rules$fallback_type,
     `:=`(attack_score = 3L, attack_type = "ddos")]
  dt[conn_count_5min >= max(3, thr_conn %/% 4) & dest_port_distinct >= max(3, thr_ports %/% 2) &
       attack_type == rules$fallback_type,
     `:=`(attack_score = 2L, attack_type = "port_scan")]
  dt[unique_dst_ip >= max(2, thr_dst %/% 2) & conn_count_5min >= 3 & attack_type == rules$fallback_type,
     `:=`(attack_score = 2L, attack_type = "botnet")]
  dt[orig_bytes > 5e4 & resp_bytes < 5e2 & conn_count_5min >= 3 & attack_type == rules$fallback_type,
     `:=`(attack_score = 2L, attack_type = "exfiltration")]
  dt[duration < 0.5 & conn_count_5min >= max(3, thr_conn %/% 4) & attack_type == rules$fallback_type,
     `:=`(attack_score = 2L, attack_type = "dos")]

  dt[(query_entropy >= rules$query_entropy | query_length >= rules$query_length) &
       attack_type == rules$fallback_type,
     `:=`(attack_score = 2L, attack_type = "dns_anomaly")]
  dt[(uri_length >= rules$uri_length | http_status_code >= 400L) &
       attack_type == rules$fallback_type,
     `:=`(attack_score = 2L, attack_type = "http_anomaly")]
  dt[ssl_sni_entropy >= rules$ssl_entropy & ssl_sni_length >= 8L &
       attack_type == rules$fallback_type,
     `:=`(attack_score = 2L, attack_type = "ssl_anomaly")]
  dt[data_volume_change >= rules$volume_pct & attack_type == rules$fallback_type,
     `:=`(attack_score = 2L, attack_type = "traffic_spike")]

  if ("service" %in% names(dt)) {
    dt[service %in% c("irc", "socks") & attack_type == rules$fallback_type,
       `:=`(attack_score = 2L, attack_type = "proxy_tunnel")]
  }

  dt
}

#' @rdname classify_attacks
#' @export
classify_attack <- classify_attacks

#' Запись алертов в JSONL
#'
#' @param alerts `data.table` алертов.
#' @param append Дописывать в файл.
#' @return Число записанных строк (невидимо).
#' @export
send_alerts <- function(alerts, append = FALSE) {
  if (!nrow(alerts)) return(invisible(0L))
  out <- PATHS$alerts_file
  dir.create(dirname(out), recursive = TRUE, showWarnings = FALSE)
  rows <- lapply(seq_len(nrow(alerts)), function(i) {
    jsonlite::toJSON(as.list(alerts[i]), auto_unbox = TRUE)
  })
  write(paste(rows, collapse = "\n"), file = out, append = isTRUE(append))
  log_info("Wrote %d alert(s) to %s", nrow(alerts), out)
  invisible(nrow(alerts))
}

#' Детектирование аномалий и классификация атак
#'
#' @param features_path Parquet с признаками.
#' @param model_path Путь к модели.
#' @param meta_path Путь к метаданным модели.
#' @return `data.table` алертов (невидимо).
#' @export
detect <- function(features_path = PATHS$features,
                   model_path    = PATHS$model_file,
                   meta_path     = PATHS$meta_file) {
  if (!file.exists(model_path)) stop("model not found: ", model_path)
  if (!file.exists(meta_path))  stop("meta not found: ", meta_path)

  feats <- data.table::as.data.table(arrow::read_parquet(features_path))
  m     <- readRDS(model_path)
  meta  <- readRDS(meta_path)

  required_cols <- meta$recipe$var_info$variable
  for (c in required_cols) {
    if (c %in% names(feats)) next
    feats[, (c) := if (c %in% CAT_FEATURES) "unknown" else FEATURE_DEFAULTS[[c]] %||% 0]
  }
  feats <- fill_defaults(feats)

  X_baked <- recipes::bake(meta$recipe, new_data = feats)

  feats[, anomaly_score := predict(m, X_baked, type = "score")]
  feats[, is_anomaly    := anomaly_score > meta$threshold]

  arrow::write_parquet(feats, PATHS$scored)
  log_info("Scored: %d rows -> %s", nrow(feats), PATHS$scored)

  alerts <- feats[is_anomaly == TRUE]
  log_info("Detect: %d / %d above threshold (%.4f)",
           nrow(alerts), nrow(feats), meta$threshold)

  if (!nrow(alerts)) return(invisible(alerts))

  alerts <- classify_attack(alerts)
  by_type <- paste(names(sort(table(alerts$attack_type), decreasing = TRUE)),
                   collapse = ", ")
  log_info("Alert types: %s", by_type)
  send_alerts(alerts)

  invisible(alerts)
}
