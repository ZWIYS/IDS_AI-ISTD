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
.load_model_meta <- function(meta_path = PATHS$meta_file) {
  if (!file.exists(meta_path)) return(NULL)
  readRDS(meta_path)
}

#' @keywords internal
.refine_alerts <- function(alerts, meta, params = DETECT_PARAMS) {
  if (!nrow(alerts)) return(alerts)
  alerts <- data.table::copy(data.table::as.data.table(alerts))

  thr <- meta$threshold %||% 0
  margin <- params$score_margin %||% 0
  if (is.finite(margin) && margin > 0) {
    alerts <- alerts[anomaly_score > thr + margin]
  }
  min_score <- params$alert_min_score %||% 0
  if (is.finite(min_score) && min_score > 0) {
    alerts <- alerts[anomaly_score >= min_score]
  }

  ml_q <- params$ml_score_quantile %||% 0
  if (is.finite(ml_q) && ml_q > 0 && ml_q < 1) {
    score_cut <- stats::quantile(alerts$anomaly_score, probs = ml_q, na.rm = TRUE)
    alerts <- alerts[
      attack_type != (params$rules$fallback_type %||% "ml_anomaly") |
        anomaly_score >= score_cut
    ]
  }

  dedup <- params$dedup_seconds %||% 0L
  if (is.finite(dedup) && dedup > 0 && "ts" %in% names(alerts)) {
    alerts[, ts_num := safe_num(ts)]
    alerts[, dedup_bucket := floor(ts_num / dedup)]
    data.table::setorder(alerts, -anomaly_score)
    alerts <- unique(
      alerts,
      by = c("src_ip", "attack_type", "dedup_bucket")
    )
    alerts[, c("ts_num", "dedup_bucket") := NULL]
  }

  alerts
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
  dt[data_volume_change >= rules$volume_pct * 0.5 & conn_count_5min >= 5 &
       attack_type == rules$fallback_type,
     `:=`(attack_score = 2L, attack_type = "traffic_spike")]
  dt[conn_count_5min >= 8 & dest_port_distinct >= 6 & attack_type == rules$fallback_type,
     `:=`(attack_score = 2L, attack_type = "port_scan")]

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
  n_raw <- nrow(alerts)
  log_info("Detect: %d / %d above threshold (%.4f)",
           n_raw, nrow(feats), meta$threshold)

  if (!nrow(alerts)) return(invisible(alerts))

  alerts <- classify_attack(alerts)
  alerts <- .refine_alerts(alerts, meta)
  if (n_raw > nrow(alerts)) {
    log_info("Alert filter: %d -> %d (margin/dedup/ml quantile)",
             n_raw, nrow(alerts))
  }
  if (!nrow(alerts)) {
    log_info("No alerts after refinement")
    return(invisible(alerts))
  }

  by_type <- paste(names(sort(table(alerts$attack_type), decreasing = TRUE)),
                   collapse = ", ")
  log_info("Alert types: %s", by_type)
  send_alerts(alerts)

  invisible(alerts)
}
