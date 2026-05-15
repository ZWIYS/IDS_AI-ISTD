#!/usr/bin/env Rscript
# =============================================================================
# run_pipeline.R — CLI-оркестратор IoT IDS (пакет idsAiIstd)
# =============================================================================
#   Rscript run_pipeline.R
#   Rscript run_pipeline.R --pcap-dir data/pcap/uploaded
#   Rscript run_pipeline.R --pcap-dir /path/to/captures data features
#
# Дашборд:
#   Rscript -e 'idsAiIstd::run_dashboard(port=4321, host="0.0.0.0")'
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
PROJECT_ROOT <- normalizePath(dirname(.script_file), mustWork = FALSE)
Sys.setenv(IDS_PROJECT_ROOT = PROJECT_ROOT, IDS_V2_ROOT = PROJECT_ROOT)

if (!requireNamespace("idsAiIstd", quietly = TRUE)) {
  if (file.exists(file.path(PROJECT_ROOT, "DESCRIPTION"))) {
    if (!requireNamespace("pkgload", quietly = TRUE)) {
      stop("Install pkgload or install idsAiIstd package first.")
    }
    pkgload::load_all(PROJECT_ROOT, quiet = TRUE)
  } else {
    stop("Package idsAiIstd not found.")
  }
} else {
  library(idsAiIstd)
}

idsAiIstd::init_ids_config(PROJECT_ROOT)

if (!is.null(pcap_dir)) {
  if (!dir.exists(pcap_dir)) stop("PCAP directory not found: ", pcap_dir)
  message("Using PCAP dir: ", pcap_dir)
}

idsAiIstd::run_ids_pipeline(stages = stages, pcap_dir = pcap_dir)
