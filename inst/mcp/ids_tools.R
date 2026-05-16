# =============================================================================
# MCP tools for IDS (sourced by mcptools::mcp_server)
# =============================================================================

if (!requireNamespace("ellmer", quietly = TRUE)) {
  stop("ellmer required for IDS MCP tools")
}

library(ellmer)

if (!exists("PATHS", envir = asNamespace("idsAiIstd"), inherits = FALSE)) {
  idsAiIstd::init_ids_config()
}

PATHS <- idsAiIstd::PATHS
PROJECT_ROOT <- idsAiIstd::PROJECT_ROOT

.ids_json <- function(x) {
  jsonlite::toJSON(x, auto_unbox = TRUE, pretty = TRUE, null = "null")
}

ids_status <- function() {
  scored_n <- if (file.exists(PATHS$scored)) {
    nrow(arrow::read_parquet(PATHS$scored))
  } else 0L
  alerts_n <- 0L
  ml_n <- 0L
  if (file.exists(PATHS$alerts_file) && file.info(PATHS$alerts_file)$size > 0) {
    lines <- readLines(PATHS$alerts_file, warn = FALSE)
    lines <- lines[nzchar(lines)]
    alerts_n <- length(lines)
    if (alerts_n) {
      dt <- data.table::rbindlist(lapply(lines, jsonlite::fromJSON), fill = TRUE)
      ml_n <- sum(dt$attack_type == "ml_anomaly", na.rm = TRUE)
    }
  }
  thr <- NA_real_
  if (file.exists(PATHS$meta_file)) {
    meta <- readRDS(PATHS$meta_file)
    thr <- meta$threshold %||% NA_real_
  }
  .ids_json(list(
    project_root = PROJECT_ROOT,
    scored_sessions = scored_n,
    alerts_count = alerts_n,
    ml_anomaly_alerts = ml_n,
    model_threshold = thr,
    paths = PATHS
  ))
}

ids_run_pipeline <- function(
  stages = "data,features,train,detect",
  reset_alerts = TRUE
) {
  st <- trimws(strsplit(stages, ",", fixed = TRUE)[[1]])
  st <- st[nzchar(st)]
  if (!length(st)) st <- c("data", "features", "train", "detect")
  idsAiIstd::run_ids_pipeline(
    stages = st,
    pcap_dir = PATHS$pcap_upload_dir,
    reset_alerts = isTRUE(reset_alerts)
  )
  ids_status()
}

ids_detect <- function() {
  idsAiIstd::detect()
  ids_status()
}

ids_list_alerts <- function(limit = 20L) {
  limit <- as.integer(limit)
  if (!file.exists(PATHS$alerts_file) || file.info(PATHS$alerts_file)$size == 0) {
    return(.ids_json(list(alerts = list(), message = "alerts.jsonl пуст")))
  }
  lines <- readLines(PATHS$alerts_file, warn = FALSE)
  lines <- lines[nzchar(lines)]
  if (!length(lines)) {
    return(.ids_json(list(alerts = list(), message = "нет строк")))
  }
  dt <- data.table::rbindlist(lapply(lines, jsonlite::fromJSON), fill = TRUE)
  data.table::setorder(dt, -ts)
  n <- min(limit, nrow(dt))
  cols <- intersect(
    c("ts", "src_ip", "dst_ip", "dst_port", "attack_type", "anomaly_score", "attack_score"),
    names(dt)
  )
  .ids_json(list(
    count = nrow(dt),
    shown = n,
    alerts = dt[seq_len(n), ..cols]
  ))
}

ids_explain_alert <- function(index = 1L) {
  index <- as.integer(index)
  if (!file.exists(PATHS$alerts_file)) {
    return(.ids_json(list(error = "alerts.jsonl не найден")))
  }
  lines <- readLines(PATHS$alerts_file, warn = FALSE)
  lines <- lines[nzchar(lines)]
  if (index < 1L || index > length(lines)) {
    return(.ids_json(list(error = sprintf("индекс вне диапазона 1..%d", length(lines)))))
  }
  row <- as.list(jsonlite::fromJSON(lines[index]))
  info <- idsAiIstd::explain_alert(row)
  .ids_json(list(alert = row, explanation = info))
}

list(
  tool(
    ids_status,
    "Состояние IDS: число сессий, алертов, порог модели, пути к файлам."
  ),
  tool(
    ids_run_pipeline,
    "Запуск batch-конвейера IDS (Zeek, features, train, detect).",
    stages = type_string(
      "Стадии через запятую: data, features, train, detect.",
      required = FALSE
    ),
    reset_alerts = type_boolean(
      "Очистить alerts.jsonl перед detect.",
      required = FALSE
    )
  ),
  tool(
    ids_detect,
    "Только стадия detect: скоринг features.parquet и запись алертов."
  ),
  tool(
    ids_list_alerts,
    "Сводка последних алертов из alerts.jsonl.",
    limit = type_integer(
      "Сколько последних алертов вернуть.",
      required = FALSE
    )
  ),
  tool(
    ids_explain_alert,
    "Пояснение сработки по номеру строки в alerts.jsonl (1 = последний по времени после сортировки).",
    index = type_integer(
      "Индекс алерта (1-based).",
      required = FALSE
    )
  )
)
