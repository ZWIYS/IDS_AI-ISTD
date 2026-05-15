# =============================================================================
# 00_config.R  —  единая конфигурация конвейера IDS
# =============================================================================
# Все пути абсолютны относительно корня v2/. Если переносишь проект — меняешь
# только PROJECT_ROOT, остальное собирается само.
# =============================================================================

# --- Корень проекта -----------------------------------------------------------
# Работает в любом из режимов: source(), Rscript, RStudio, knitr, shiny.
.find_this_dir <- function() {
  # 0) Явный env var от оркестратора run_pipeline.R (самый надёжный)
  env_root <- Sys.getenv("IDS_V2_ROOT", "")
  if (nzchar(env_root)) return(normalizePath(file.path(env_root, "R"), mustWork = FALSE))
  # 1) Rscript — берём путь к текущему скрипту
  args <- commandArgs(trailingOnly = FALSE)
  fn   <- sub("^--file=", "", grep("^--file=", args, value = TRUE))
  if (length(fn)) return(normalizePath(dirname(fn), mustWork = FALSE))
  # 2) source()
  d <- tryCatch(dirname(sys.frame(1)$ofile), error = function(e) NULL)
  if (!is.null(d) && nzchar(d)) return(normalizePath(d, mustWork = FALSE))
  # 3) RStudio
  d <- tryCatch(dirname(rstudioapi::getSourceEditorContext()$path),
                error = function(e) NULL)
  if (!is.null(d) && nzchar(d)) return(normalizePath(d, mustWork = FALSE))
  # 4) fallback
  normalizePath(getwd(), mustWork = FALSE)
}
.this_dir   <- .find_this_dir()
PROJECT_ROOT <- normalizePath(file.path(.this_dir, ".."), mustWork = FALSE)

# --- Пути ---------------------------------------------------------------------
PATHS <- list(
  pcap_dir        = file.path(PROJECT_ROOT, "data", "pcap"),
  pcap_upload_dir = file.path(PROJECT_ROOT, "data", "pcap", "uploaded"),
  zeek_logs_dir  = file.path(PROJECT_ROOT, "data", "zeek_logs"),
  processed_dir  = file.path(PROJECT_ROOT, "data", "processed"),
  models_dir     = file.path(PROJECT_ROOT, "models"),
  alerts_dir     = file.path(PROJECT_ROOT, "alerts"),
  dataset        = file.path(PROJECT_ROOT, "data", "processed", "dataset.parquet"),
  features       = file.path(PROJECT_ROOT, "data", "processed", "features.parquet"),
  scored         = file.path(PROJECT_ROOT, "data", "processed", "scored.parquet"),
  model_file     = file.path(PROJECT_ROOT, "models", "iforest.rds"),
  meta_file      = file.path(PROJECT_ROOT, "models", "model_meta.rds"),
  alerts_file    = file.path(PROJECT_ROOT, "alerts", "alerts.jsonl"),
  block_script   = file.path(PROJECT_ROOT, "scripts", "block_ip.sh")
)

# Создаём всё нужное
for (p in PATHS[grepl("_dir$", names(PATHS))]) {
  dir.create(p, recursive = TRUE, showWarnings = FALSE)
}

# --- Бинарь Zeek --------------------------------------------------------------
ZEEK_BIN <- Sys.getenv("ZEEK_BIN", "zeek")

# --- Параметры модели ---------------------------------------------------------
MODEL_PARAMS <- list(
  ntrees           = 200,
  sample_size      = 256,
  max_depth        = 100,
  ndim             = 1,            # 1 = классический iForest, 2+ = extended
  contamination    = 0.01,         # ожидаемая доля атак (1%)
  threshold_quant  = 0.99,         # верхний 1% по score = аномалия
  seed             = 42,
  nthreads         = max(1, parallel::detectCores() - 1)
)

# --- Параметры детектора ------------------------------------------------------
DETECT_PARAMS <- list(
  window_seconds   = 300,           # 5 мин — окно агрегации
  alert_min_score  = 0.55,          # минимальный score для алерта
  enable_blocking  = FALSE,         # включи в проде осознанно
  dedup_seconds    = 60,            # не дублировать алерт от того же src→dst чаще раза в 60с
  # Пороги rule-based классификатора (адаптивные + строгие)
  rules = list(
    adaptive_frac  = 0.75,          # доля от макс. в батче для «малых» PCAP
    query_entropy  = 3.0,           # DNS: подозрительная энтропия
    query_length   = 40L,
    uri_length     = 150L,
    ssl_entropy    = 3.0,
    volume_pct     = 150,           # data_volume_change, %
    fallback_type  = "ml_anomaly"   # если ни одно правило не сработало
  )
)

# --- Загрузка пакетов ---------------------------------------------------------
ensure_packages <- function(pkgs) {
  missing <- pkgs[!vapply(pkgs, requireNamespace, logical(1), quietly = TRUE)]
  if (length(missing)) {
    if (identical(Sys.getenv("CI"), "true")) {
      stop(
        "Missing R packages in CI: ", paste(missing, collapse = ", "),
        ". Install via DESCRIPTION + install_dependencies.R before running tests."
      )
    }
    install.packages(missing, repos = "https://cloud.r-project.org")
  }
  invisible(lapply(pkgs, function(p) suppressPackageStartupMessages(
    library(p, character.only = TRUE)
  )))
}

REQUIRED_PKGS <- c(
  "data.table", "arrow", "digest", "processx", "jsonlite", "stringi",
  "isotree",
  "recipes",
  "rsample"
)

# Опционально (для дашборда / отчётов)
OPTIONAL_PKGS <- c("shiny", "DT", "plotly", "bslib")
