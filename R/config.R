# =============================================================================
# config.R — конфигурация конвейера IDS (пакет idsAiIstd)
# =============================================================================

#' Инициализация путей и параметров конвейера
#'
#' Задаёт `PROJECT_ROOT`, `PATHS`, `MODEL_PARAMS`, `DETECT_PARAMS` и `ZEEK_BIN`
#' в пространстве имён пакета. Вызывается автоматически при загрузке пакета;
#' для CLI укажите корень проекта через `root` или переменную окружения
#' `IDS_PROJECT_ROOT` (также поддерживается устаревшая `IDS_V2_ROOT`).
#'
#' @param root Корень проекта (каталоги `data/`, `models/`, `alerts/`).
#'   По умолчанию — из env или `getwd()`.
#' @return Список с элементами `PROJECT_ROOT`, `PATHS`, `MODEL_PARAMS`,
#'   `DETECT_PARAMS`, `ZEEK_BIN` (невидимо).
#' @export
init_ids_config <- function(root = NULL) {
  if (is.null(root)) root <- .default_project_root()
  root <- normalizePath(root, mustWork = FALSE)

  block_inst <- system.file("scripts", "block_ip.sh", package = "idsAiIstd")
  block_script <- if (nzchar(block_inst)) {
    block_inst
  } else {
    file.path(root, "scripts", "block_ip.sh")
  }

  paths <- list(
    pcap_dir        = file.path(root, "data", "pcap"),
    pcap_upload_dir = file.path(root, "data", "pcap", "uploaded"),
    zeek_logs_dir   = file.path(root, "data", "zeek_logs"),
    processed_dir   = file.path(root, "data", "processed"),
    models_dir      = file.path(root, "models"),
    alerts_dir      = file.path(root, "alerts"),
    dataset         = file.path(root, "data", "processed", "dataset.parquet"),
    features        = file.path(root, "data", "processed", "features.parquet"),
    scored          = file.path(root, "data", "processed", "scored.parquet"),
    model_file      = file.path(root, "models", "iforest.rds"),
    meta_file       = file.path(root, "models", "model_meta.rds"),
    alerts_file     = file.path(root, "alerts", "alerts.jsonl"),
    block_script    = block_script
  )

  for (p in paths[grepl("_dir$", names(paths))]) {
    dir.create(p, recursive = TRUE, showWarnings = FALSE)
  }

  model_params <- list(
    ntrees          = 200L,
    sample_size     = 256L,
    max_depth       = 100L,
    ndim            = 1L,
    contamination   = 0.01,
    threshold_quant = 0.995,
    seed            = 42L,
    nthreads        = max(1L, parallel::detectCores() - 1L)
  )

  detect_params <- list(
    window_seconds  = 300L,
    alert_min_score = 0,
    score_margin    = 0.02,
    ml_score_quantile = 0.80,
    enable_blocking = FALSE,
    dedup_seconds   = 120L,
    rules = list(
      adaptive_frac = 0.75,
      query_entropy = 3.0,
      query_length  = 40L,
      uri_length    = 150L,
      ssl_entropy   = 3.0,
      volume_pct    = 150,
      fallback_type = "ml_anomaly"
    )
  )

  zeek_bin <- Sys.getenv("ZEEK_BIN", "zeek")

  ns <- asNamespace("idsAiIstd")
  bindings <- list(
    PROJECT_ROOT  = root,
    PATHS         = paths,
    MODEL_PARAMS  = model_params,
    DETECT_PARAMS = detect_params,
    ZEEK_BIN      = zeek_bin
  )
  for (n in names(bindings)) {
    .pkg_assign(n, bindings[[n]], ns)
  }

  invisible(list(
    PROJECT_ROOT  = root,
    PATHS         = paths,
    MODEL_PARAMS  = model_params,
    DETECT_PARAMS = detect_params,
    ZEEK_BIN      = zeek_bin
  ))
}

#' @keywords internal
.pkg_assign <- function(name, value, ns) {
  if (exists(name, envir = ns, inherits = FALSE) && bindingIsLocked(name, ns)) {
    unlockBinding(name, ns)
  }
  assign(name, value, envir = ns)
}

.default_project_root <- function() {
  for (v in c("IDS_PROJECT_ROOT", "IDS_V2_ROOT")) {
    x <- Sys.getenv(v, "")
    if (nzchar(x)) return(normalizePath(x, mustWork = FALSE))
  }
  normalizePath(getwd(), mustWork = FALSE)
}
