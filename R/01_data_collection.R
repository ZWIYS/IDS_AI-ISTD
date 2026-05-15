# =============================================================================
# 01_data_collection.R — БЛОКИ 1+2: Сбор данных + ETL
# =============================================================================
# 1) Запуск Zeek по PCAP-файлам (кеш по hash(содержимое), не по имени)
# 2) Парсинг conn.log + dns.log + http.log + ssl.log
# 3) Объединение по uid -> одна conn-level запись с DNS/HTTP/SSL атрибутами
# 4) Нормализация: id.orig_h -> src_ip, id.resp_h -> dst_ip и пр.
# Результат: data/processed/dataset.parquet
# =============================================================================

local({
  here <- tryCatch(dirname(sys.frame(1)$ofile), error = function(e) getwd())
  source(file.path(here, "00_config.R"), chdir = TRUE)
  source(file.path(here, "utils.R"),     chdir = TRUE)
})
ensure_packages(REQUIRED_PKGS)

# --- Запуск Zeek с кешем по содержимому PCAP ---------------------------------
run_zeek <- function(pcap_path) {
  pcap_path <- normalizePath(pcap_path, mustWork = TRUE)
  cache_key <- digest::digest(file = pcap_path, algo = "md5")
  out_dir   <- file.path(PATHS$zeek_logs_dir, cache_key)
  marker    <- file.path(out_dir, ".done")

  if (file.exists(marker)) {
    log_info("Zeek cache hit: %s", basename(pcap_path))
    return(out_dir)
  }
  dir.create(out_dir, recursive = TRUE, showWarnings = FALSE)

  log_info("Zeek run: %s", basename(pcap_path))
  res <- processx::run(
    ZEEK_BIN,
    args = c("-r", pcap_path, "LogAscii::use_json=F"),
    wd = out_dir, error_on_status = FALSE, timeout = 600
  )
  if (res$status != 0L) {
    stop(sprintf("Zeek failed on %s:\n%s", basename(pcap_path), res$stderr))
  }
  file.create(marker)
  out_dir
}

# --- Загрузка conn.log + переименование Zeek-полей ---------------------------
load_conn <- function(zeek_dir) {
  dt <- read_zeek_tsv(file.path(zeek_dir, "conn.log"))
  if (is.null(dt) || !nrow(dt)) return(NULL)

  # Переименуем "точечные" Zeek-поля в plain имена
  ren <- c(
    "id.orig_h" = "src_ip",  "id.orig_p" = "src_port",
    "id.resp_h" = "dst_ip",  "id.resp_p" = "dst_port"
  )
  present <- intersect(names(ren), names(dt))
  if (length(present)) data.table::setnames(dt, present, ren[present])

  num_cols <- c("ts","duration","orig_bytes","resp_bytes","missed_bytes",
                "orig_pkts","resp_pkts","orig_ip_bytes","resp_ip_bytes",
                "src_port","dst_port")
  for (c in intersect(num_cols, names(dt))) dt[, (c) := safe_num(get(c))]

  for (c in c("proto","service","conn_state","history","uid")) {
    if (c %in% names(dt)) dt[, (c) := as.character(get(c))]
  }
  dt
}

# --- Извлечение DNS/HTTP/SSL атрибутов на уровне uid -------------------------
enrich_dns <- function(zeek_dir) {
  d <- read_zeek_tsv(file.path(zeek_dir, "dns.log"))
  if (is.null(d) || !"uid" %in% names(d)) return(NULL)
  q <- as.character(safe_col(d, "query", ""))
  d[, query_length  := nchar(q %||% "")]
  d[, query_entropy := shannon_entropy_v(q)]
  d[, num_labels    := stringi::stri_count_fixed(q, ".") + 1L]
  d[, .(
    query_length  = safe_max(query_length),
    query_entropy = safe_max(query_entropy),
    num_labels    = safe_max(num_labels)
  ), by = uid]
}

enrich_http <- function(zeek_dir) {
  d <- read_zeek_tsv(file.path(zeek_dir, "http.log"))
  if (is.null(d) || !"uid" %in% names(d)) return(NULL)
  uri <- as.character(safe_col(d, "uri", ""))
  ua  <- as.character(safe_col(d, "user_agent", ""))
  d[, uri_length := nchar(uri %||% "")]
  d[, ua_length  := nchar(ua  %||% "")]
  d[, status_n   := safe_num(safe_col(d, "status_code", 0))]
  d[, method_c   := as.character(safe_col(d, "method", NA))]
  d[, .(
    uri_length       = safe_max(uri_length),
    ua_length        = safe_max(ua_length),
    http_status_code = safe_max(status_n),
    http_method      = method_c[1]
  ), by = uid]
}

enrich_ssl <- function(zeek_dir) {
  d <- read_zeek_tsv(file.path(zeek_dir, "ssl.log"))
  if (is.null(d) || !"uid" %in% names(d)) return(NULL)
  sni <- as.character(safe_col(d, "server_name", ""))
  d[, ssl_sni_length  := nchar(sni %||% "")]
  d[, ssl_sni_entropy := shannon_entropy_v(sni)]
  d[, .(
    ssl_sni_length  = safe_max(ssl_sni_length),
    ssl_sni_entropy = safe_max(ssl_sni_entropy)
  ), by = uid]
}

join_uid <- function(conn, aux) {
  if (is.null(aux) || !nrow(aux)) return(conn)
  conn[aux, on = "uid", (setdiff(names(aux), "uid")) :=
         mget(paste0("i.", setdiff(names(aux), "uid")))]
  conn
}

process_pcap <- function(pcap_path) {
  z   <- run_zeek(pcap_path)
  dt  <- load_conn(z); if (is.null(dt)) return(NULL)
  dt  <- join_uid(dt, enrich_dns(z))
  dt  <- join_uid(dt, enrich_http(z))
  dt  <- join_uid(dt, enrich_ssl(z))
  dt[, source_file := basename(pcap_path)]
  dt
}

# --- Главный конвейер ETL ----------------------------------------------------
run_etl <- function(pcap_dir = PATHS$pcap_dir, out_path = PATHS$dataset) {
  pcaps <- list.files(pcap_dir, "\\.(pcap|pcapng)(\\.gz)?$",
                      full.names = TRUE, ignore.case = TRUE)
  if (!length(pcaps)) stop("No PCAPs in: ", pcap_dir)
  log_info("ETL: %d PCAPs", length(pcaps))

  parts <- lapply(pcaps, function(p) {
    tryCatch(process_pcap(p),
             error = function(e) { log_error("Failed %s: %s", basename(p), e$message); NULL })
  })
  out <- data.table::rbindlist(parts, fill = TRUE)
  if (!nrow(out)) stop("ETL produced zero rows")

  arrow::write_parquet(out, out_path)
  log_info("ETL done: %d rows -> %s", nrow(out), out_path)
  invisible(out)
}

# Если файл запущен напрямую — выполнить
if (sys.nframe() == 0L) run_etl()
