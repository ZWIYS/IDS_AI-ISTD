# =============================================================================
# pipeline_runner.R — запуск стадий конвейера (CLI и Shiny)
# =============================================================================

STAGE_MAP <- list(
  data     = list(file = "01_data_collection.R",     fun = "run_etl"),
  features = list(file = "02_feature_engineering.R", fun = "build_features"),
  train    = list(file = "03_ml_training.R",         fun = "train_iforest"),
  detect   = list(file = "04_attack_detection.R",    fun = "detect")
)

run_ids_pipeline <- function(
  stages       = c("data", "features", "train", "detect"),
  pcap_dir     = NULL,
  reset_alerts = TRUE  # в Shiny: FALSE, если «Заменить ранее загруженные» выключен
) {
  r_dir <- file.path(PROJECT_ROOT, "R")
  if (isTRUE(reset_alerts) && "detect" %in% stages && file.exists(PATHS$alerts_file))
    writeLines(character(), PATHS$alerts_file)

  for (name in stages) {
    s <- STAGE_MAP[[name]]
    if (is.null(s)) stop("Unknown stage: ", name,
                         " (use: ", paste(names(STAGE_MAP), collapse = ", "), ")")
    log_info("==== STAGE: %s (%s) ====", toupper(name), s$file)
    t0 <- Sys.time()
    source(file.path(r_dir, s$file), chdir = TRUE)
    args <- list()
    if (identical(name, "data") && !is.null(pcap_dir)) args$pcap_dir <- pcap_dir
    do.call(s$fun, args)
    log_info("==== %s done in %.2fs ====", toupper(name),
             as.numeric(difftime(Sys.time(), t0, units = "secs")))
  }
  log_info("Pipeline complete.")
  invisible(TRUE)
}
