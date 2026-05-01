# =============================
# DEPENDENCIES
# =============================
packages <- c("data.table", "processx", "arrow", "digest")

for (p in packages) {
  if (!require(p, character.only = TRUE)) {
    install.packages(p)
    library(p, character.only = TRUE)
  }
}

# =============================
# CONFIG
# =============================
ZEEK_BIN <- "zeek"
INPUT_DIR <- "pcap"
OUTPUT_DIR <- "output"
ZEEK_LOG_DIR <- file.path(OUTPUT_DIR, "zeek_logs")

dir.create(OUTPUT_DIR, showWarnings = FALSE, recursive = TRUE)
dir.create(ZEEK_LOG_DIR, showWarnings = FALSE, recursive = TRUE)

# =============================
# UTILS
# =============================
log_msg <- function(...) {
  cat(sprintf(...), "\n")
}

safe_num <- function(x, n) {
  if (is.null(x)) return(rep(0, n))
  x <- suppressWarnings(as.numeric(x))
  x[is.na(x)] <- 0
  x
}

clean_zeek_na <- function(dt) {
  na_vals <- c("-", "", "(empty)", "(unset)")
  for (col in names(dt)) {
    dt[get(col) %in% na_vals, (col) := NA]
  }
  dt
}

# =============================
# RUN ZEEK (FIXED PATH ISSUE)
# =============================
run_zeek <- function(pcap_path) {
  
  # 🔥 КРИТИЧЕСКИЙ ФИКС
  pcap_path <- normalizePath(pcap_path)
  
  hash <- digest::digest(pcap_path, algo = "md5")
  out_dir <- file.path(ZEEK_LOG_DIR, hash)
  
  dir.create(out_dir, recursive = TRUE, showWarnings = FALSE)
  
  marker <- file.path(out_dir, ".done")
  
  if (file.exists(marker)) {
    log_msg("Cached: %s", basename(pcap_path))
    return(out_dir)
  }
  
  log_msg("Running Zeek: %s", basename(pcap_path))
  
  res <- processx::run(
    ZEEK_BIN,
    args = c("-r", pcap_path),
    wd = out_dir,
    error_on_status = FALSE
  )
  
  if (res$status != 0) {
    stop(sprintf("Zeek failed:\n%s", res$stderr))
  }
  
  file.create(marker)
  out_dir
}

# =============================
# READ conn.log
# =============================
read_conn_log <- function(file_path) {
  
  if (!file.exists(file_path)) {
    log_msg("No conn.log: %s", file_path)
    return(NULL)
  }
  
  lines <- readLines(file_path, warn = FALSE)
  fields_idx <- grep("^#fields", lines)
  
  if (length(fields_idx) == 0 || fields_idx[1] >= length(lines)) {
    log_msg("Broken log: %s", file_path)
    return(NULL)
  }
  
  headers <- strsplit(sub("^#fields\\s+", "", lines[fields_idx[1]]), "\\s+")[[1]]
  data_lines <- lines[(fields_idx[1] + 1):length(lines)]
  
  dt <- tryCatch({
    data.table::fread(
      text = data_lines,
      sep = "\t",
      header = FALSE,
      showProgress = FALSE
    )
  }, error = function(e) {
    log_msg("Read error: %s", file_path)
    return(NULL)
  })
  
  if (is.null(dt) || ncol(dt) != length(headers)) {
    log_msg("Column mismatch: %s", file_path)
    return(NULL)
  }
  
  setnames(dt, headers)
  dt <- clean_zeek_na(dt)
  
  dt
}

# =============================
# FEATURE ENGINEERING
# =============================
add_features <- function(dt) {
  
  if (is.null(dt) || nrow(dt) == 0) return(NULL)
  
  n <- nrow(dt)
  
  dt[, orig_bytes := safe_num(orig_bytes, n)]
  dt[, resp_bytes := safe_num(resp_bytes, n)]
  dt[, duration := safe_num(duration, n)]
  dt[, orig_pkts := safe_num(orig_pkts, n)]
  dt[, resp_pkts := safe_num(resp_pkts, n)]
  
  dt[, total_bytes := orig_bytes + resp_bytes]
  dt[, bytes_per_sec := ifelse(duration > 0, total_bytes / duration, 0)]
  dt[, pkt_ratio := ifelse(resp_pkts > 0, orig_pkts / resp_pkts, 0)]
  
  dt
}

# =============================
# MAIN PIPELINE
# =============================
process_all_pcaps <- function() {
  
  pcap_files <- list.files(INPUT_DIR, pattern = "\\.pcap$", full.names = TRUE)
  
  if (length(pcap_files) == 0) {
    stop("No PCAP files found")
  }
  
  log_msg("Found %d PCAP files", length(pcap_files))
  
  results_list <- lapply(pcap_files, function(pcap) {
    
    tryCatch({
      
      log_msg("Processing: %s", basename(pcap))
      
      zeek_dir <- run_zeek(pcap)
      conn_path <- file.path(zeek_dir, "conn.log")
      
      dt <- read_conn_log(conn_path)
      
      if (is.null(dt) || nrow(dt) == 0) {
        log_msg("Empty or missing data: %s", basename(pcap))
        return(NULL)
      }
      
      dt <- add_features(dt)
      dt[, source_file := basename(pcap)]
      
      dt
      
    }, error = function(e) {
      log_msg("FAILED: %s | %s", basename(pcap), e$message)
      return(NULL)
    })
    
  })
  
  all_data <- data.table::rbindlist(results_list, fill = TRUE)
  
  if (is.null(all_data) || nrow(all_data) == 0) {
    stop("No data extracted from any PCAP")
  }
  
  log_msg("Total rows: %d", nrow(all_data))
  
  # =============================
  # SAVE OUTPUT
  # =============================
  parquet_path <- file.path(OUTPUT_DIR, "dataset.parquet")
  csv_path <- file.path(OUTPUT_DIR, "dataset.csv")
  
  log_msg("Saving Parquet...")
  arrow::write_parquet(all_data, parquet_path)
  
  log_msg("Saving CSV...")
  data.table::fwrite(all_data, csv_path)
  
  log_msg("DONE")
  
  invisible(all_data)
}

# =============================
# RUN
# =============================
process_all_pcaps()