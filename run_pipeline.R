#!/usr/bin/env Rscript
# =============================================================================
# run_pipeline.R — Главный оркестратор IoT IDS
# =============================================================================
# Запускает batch-стадии:
#   data -> features -> train -> detect
#
# Использование:
#   Rscript run_pipeline.R
#   Rscript run_pipeline.R --pcap-dir data/pcap/uploaded
#   Rscript run_pipeline.R --pcap-dir /path/to/captures data features
#
# Дашборд (загрузка PCAP через UI):
#   Rscript -e 'shiny::runApp("R/05_dashboard.R", port=4321, host="0.0.0.0")'
# =============================================================================

raw_args <- commandArgs(trailingOnly = TRUE)
pcap_dir <- NULL
stages   <- raw_args

idx <- which(stages == "--pcap-dir")
if (length(idx)) {
  if (idx == length(stages)) stop("--pcap-dir requires a path argument")
  pcap_dir <- normalizePath(stages[idx + 1], mustWork = FALSE)
  stages   <- stages[-c(idx, idx + 1)]
}
if (!length(stages)) stages <- c("data", "features", "train", "detect")

.script_file <- normalizePath(
  sub("^--file=", "", grep("^--file=", commandArgs(FALSE), value = TRUE)),
  mustWork = FALSE
)
V2_ROOT <- normalizePath(dirname(.script_file), mustWork = FALSE)
R_DIR   <- file.path(V2_ROOT, "R")

Sys.setenv(IDS_V2_ROOT = V2_ROOT)

source(file.path(R_DIR, "00_config.R"), chdir = TRUE)
source(file.path(R_DIR, "utils.R"),     chdir = TRUE)
source(file.path(R_DIR, "pipeline_runner.R"), chdir = TRUE)

if (!is.null(pcap_dir)) {
  if (!dir.exists(pcap_dir)) stop("PCAP directory not found: ", pcap_dir)
  log_info("Using PCAP dir: %s", pcap_dir)
}

run_ids_pipeline(stages = stages, pcap_dir = pcap_dir)
