# =============================================================================
# 02_feature_engineering.R — БЛОК 3: Feature engineering
# =============================================================================
# Conn-level: total_bytes, bytes_per_sec, pkt_ratio, history_length
# Окно (5 мин per src_ip): conn_count_5min, dest_port_distinct, unique_dst_ip,
#                          bytes_5min, data_volume_change(%)
# DNS:  query_length, query_entropy, num_labels
# HTTP: uri_length, ua_length, http_status_code
# SSL:  ssl_sni_length, ssl_sni_entropy
# Категориальные: proto, service, conn_state
# Результат: data/processed/features.parquet
# =============================================================================

local({
  here <- tryCatch(dirname(sys.frame(1)$ofile), error = function(e) getwd())
  source(file.path(here, "00_config.R"), chdir = TRUE)
  source(file.path(here, "utils.R"),     chdir = TRUE)
})
ensure_packages(REQUIRED_PKGS)

# Полный список ML-признаков с дефолтами. Если фичи нет в источнике — нулим.
FEATURE_DEFAULTS <- list(
  duration         = 0, orig_bytes       = 0, resp_bytes       = 0,
  missed_bytes     = 0, orig_pkts        = 0, resp_pkts        = 0,
  total_bytes      = 0, bytes_per_sec    = 0, pkt_ratio        = 0,
  history_length   = 0,
  uri_length       = 0, ua_length        = 0, http_status_code = 0,
  query_length     = 0, query_entropy    = 0, num_labels       = 0,
  ssl_sni_length   = 0, ssl_sni_entropy  = 0,
  conn_count_5min      = 0, dest_port_distinct = 0,
  unique_dst_ip        = 0, bytes_5min         = 0,
  data_volume_change   = 0
)
NUM_FEATURES <- names(FEATURE_DEFAULTS)
CAT_FEATURES <- c("proto", "service", "conn_state")

# --- Conn-level производные --------------------------------------------------
add_conn_features <- function(dt) {
  for (c in c("orig_bytes","resp_bytes","duration","orig_pkts","resp_pkts","missed_bytes")) {
    if (!c %in% names(dt)) dt[, (c) := 0]
    dt[, (c) := safe_num(get(c))]
  }
  dt[, total_bytes    := orig_bytes + resp_bytes]
  dt[, bytes_per_sec  := data.table::fifelse(duration > 0, total_bytes / duration, 0)]
  dt[, pkt_ratio      := data.table::fifelse(resp_pkts > 0, orig_pkts / resp_pkts, 0)]
  dt[, history_length := nchar(safe_col(dt, "history", "") %||% "")]
  dt
}

# --- Sliding window: фиксированные buckets по floor(ts/window) ---------------
# Простой и быстрый подход. Для прод-системы стоит non-equi self-join,
# но для batch-обучения buckets дают такую же сигнатуру атаки.
add_window_features <- function(dt, win = DETECT_PARAMS$window_seconds) {
  if (!"src_ip" %in% names(dt)) { log_warn("no src_ip — skip window agg"); return(dt) }
  if (!"ts" %in% names(dt))     { log_warn("no ts — skip window agg");     return(dt) }
  if (!"dst_port" %in% names(dt)) dt[, dst_port := NA_integer_]
  if (!"dst_ip"   %in% names(dt)) dt[, dst_ip   := NA_character_]
  dt[, ts := safe_num(ts)]
  dt[, bucket := as.integer(floor(ts / win))]

  agg <- dt[, .(
    conn_count_5min    = .N,
    dest_port_distinct = data.table::uniqueN(dst_port),
    unique_dst_ip      = data.table::uniqueN(dst_ip),
    bytes_5min         = sum(total_bytes, na.rm = TRUE)
  ), by = .(src_ip, bucket)]

  # Δ-объёма к предыдущему окну (в %), монотонно по времени
  data.table::setorder(agg, src_ip, bucket)
  agg[, prev_bytes := data.table::shift(bytes_5min), by = src_ip]
  agg[, data_volume_change := data.table::fifelse(
    is.na(prev_bytes) | prev_bytes == 0, 0,
    100 * (bytes_5min - prev_bytes) / prev_bytes
  )]
  agg[, prev_bytes := NULL]

  dt[agg, on = .(src_ip, bucket),
     `:=`(conn_count_5min    = i.conn_count_5min,
          dest_port_distinct = i.dest_port_distinct,
          unique_dst_ip      = i.unique_dst_ip,
          bytes_5min         = i.bytes_5min,
          data_volume_change = i.data_volume_change)]
  dt[, bucket := NULL]
  dt
}

# --- Гарантия наличия всех ML-колонок с дефолтами ----------------------------
fill_defaults <- function(dt) {
  dt <- data.table::as.data.table(dt)
  for (col in names(FEATURE_DEFAULTS)) {
    def <- FEATURE_DEFAULTS[[col]]
    if (!col %in% names(dt)) {
      dt[, (col) := def]
    } else {
      dt[, (col) := safe_num(get(col))]
    }
  }
  for (col in CAT_FEATURES) {
    if (!col %in% names(dt)) {
      dt[, (col) := "unknown"]
    } else {
      dt[is.na(get(col)) | get(col) == "", (col) := "unknown"]
    }
  }
  dt
}

build_features <- function(in_path = PATHS$dataset, out_path = PATHS$features) {
  if (!file.exists(in_path)) stop("dataset not found: ", in_path)
  log_info("Features: load %s", in_path)
  dt <- data.table::as.data.table(arrow::read_parquet(in_path))

  dt <- add_conn_features(dt)
  dt <- add_window_features(dt)
  dt <- fill_defaults(dt)

  arrow::write_parquet(dt, out_path)
  log_info("Features: %d rows, %d cols -> %s", nrow(dt), ncol(dt), out_path)
  invisible(dt)
}

if (sys.nframe() == 0L) build_features()
