# =============================================================================
# feature-engineering.R — признаки для ML и rule-based детектора
# =============================================================================

#' @keywords internal
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

#' @keywords internal
NUM_FEATURES <- names(FEATURE_DEFAULTS)

#' @keywords internal
CAT_FEATURES <- c("proto", "service", "conn_state")

#' @keywords internal
add_conn_features <- function(dt) {
  for (c in c("orig_bytes", "resp_bytes", "duration", "orig_pkts", "resp_pkts", "missed_bytes")) {
    if (!c %in% names(dt)) dt[, (c) := 0]
    dt[, (c) := safe_num(get(c))]
  }
  dt[, total_bytes    := orig_bytes + resp_bytes]
  dt[, bytes_per_sec  := data.table::fifelse(duration > 0, total_bytes / duration, 0)]
  dt[, pkt_ratio      := data.table::fifelse(resp_pkts > 0, orig_pkts / resp_pkts, 0)]
  dt[, history_length := nchar(safe_col(dt, "history", "") %||% "")]
  dt
}

#' @keywords internal
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

#' @keywords internal
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

#' Построение признаков из dataset.parquet
#'
#' @param in_path Входной parquet.
#' @param out_path Выходной parquet.
#' @return `data.table` (невидимо).
#' @export
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
