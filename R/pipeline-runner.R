# =============================================================================
# pipeline-runner.R — запуск стадий конвейера (CLI и Shiny)
# =============================================================================

#' @keywords internal
STAGE_MAP <- list(
  data     = run_etl,
  features = build_features,
  train    = train_iforest,
  detect   = detect
)

#' Запуск batch-конвейера IDS
#'
#' @param stages Имена стадий: `data`, `features`, `train`, `detect`.
#' @param pcap_dir Каталог PCAP для стадии `data` (опционально).
#' @param reset_alerts Очистить `alerts.jsonl` перед detect.
#' @return `TRUE` (невидимо).
#' @export
run_ids_pipeline <- function(
  stages       = c("data", "features", "train", "detect"),
  pcap_dir     = NULL,
  reset_alerts = TRUE
) {
  if (isTRUE(reset_alerts) && "detect" %in% stages && file.exists(PATHS$alerts_file)) {
    writeLines(character(), PATHS$alerts_file)
  }

  for (name in stages) {
    fn <- STAGE_MAP[[name]]
    if (is.null(fn)) {
      stop("Unknown stage: ", name,
           " (use: ", paste(names(STAGE_MAP), collapse = ", "), ")")
    }
    log_info("==== STAGE: %s ====", toupper(name))
    t0 <- Sys.time()
    args <- list()
    if (identical(name, "data") && !is.null(pcap_dir)) args$pcap_dir <- pcap_dir
    do.call(fn, args)
    log_info("==== %s done in %.2fs ====", toupper(name),
             as.numeric(difftime(Sys.time(), t0, units = "secs")))
  }
  log_info("Pipeline complete.")
  invisible(TRUE)
}
