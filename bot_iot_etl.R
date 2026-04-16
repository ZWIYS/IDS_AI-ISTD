#!/usr/bin/env Rscript
# =============================================================================
# bot_iot_etl.R
# ETL-модуль для обработки PCAP-файлов датасета BoT-IoT (UNSW)
# для использования в системах обнаружения вторжений (IDS) в сети IoT
#
# Источник датасета:
#   Koroniotis et al. "Towards the development of realistic botnet dataset
#   in the internet of things for network forensic analytics: Bot-iot dataset."
#   Future Generation Computer Systems 100 (2019): 779-796.
#
# Архитектура пайплайна:
#   [PCAP] → extract() → transform() → load() → [Parquet / CSV]
#
# Зависимости (системные):
#   tshark   (Wireshark CLI)  — извлечение полей пакетов
#   argus    (опционально)    — генерация flow-записей
#   ra       (опционально)    — чтение argus-файлов
#
# Зависимости (R-пакеты):
#   data.table, dplyr, tidyr, stringr, lubridate,
#   arrow (Parquet), logger, R.utils
# =============================================================================

#!/usr/bin/env Rscript

# UTF-8 FIX (NO LOG NOISE)
options(encoding = "UTF-8")
invisible(try(Sys.setlocale("LC_ALL", "en_US.UTF-8"), silent = TRUE))

suppressPackageStartupMessages({
  library(data.table)
  library(dplyr)
  library(tidyr)
  library(stringr)
  library(lubridate)
  library(arrow)
  library(logger)
  library(R.utils)
})

# -----------------------------------------------------------------------------
# 0. КОНФИГУРАЦИЯ
# -----------------------------------------------------------------------------

ETL_CONFIG <- list(
  pcap_dir      = "data/raw/pcap",
  csv_dir       = "data/raw/csv",
  output_dir    = "data/processed",
  log_file      = "logs/etl_bot_iot.log",

  tshark_bin    = "tshark",
  tshark_fields = c(
    "frame.time_epoch",
    "ip.src", "ip.dst",
    "tcp.srcport", "tcp.dstport",
    "udp.srcport", "udp.dstport",
    "ip.proto",
    "frame.len",
    "ip.ttl",
    "tcp.flags",
    "tcp.window_size_value",
    "tcp.analysis.ack_rtt",
    "icmp.type",
    "dns.qry.name",
    "http.request.method",
    "mqtt.msgtype"
  ),

  flow_timeout_sec = 120,
  attack_categories = c(
    "DDoS", "DoS", "Reconnaissance",
    "Theft",
    "Normal"
  ),
  normalize_method  = "min-max",
  random_seed = 42L,
  n_workers = max(1L, parallel::detectCores() - 1L)
)

# -----------------------------------------------------------------------------
# 1. УТИЛИТЫ
# -----------------------------------------------------------------------------

#' Инициализировать систему логирования
init_logger <- function(log_file) {
  dir.create(dirname(log_file), showWarnings = FALSE, recursive = TRUE)
  log_appender(appender_tee(log_file))
  log_threshold(INFO)
  log_formatter(formatter_glue_or_sprintf)
  log_info("=== BoT-IoT ETL initialized ===")
}

#' Проверить наличие системных зависимостей
check_dependencies <- function() {
  log_info("Checking system dependencies...")
  bins <- c(ETL_CONFIG$tshark_bin)
  missing <- bins[!nzchar(Sys.which(bins))]
  if (length(missing) > 0) {
    stop(sprintf("System dependencies not found: %s\n  Install: sudo apt-get install tshark",
                 paste(missing, collapse = ", ")))
  }
  log_info("Dependencies OK: {paste(bins, collapse=', ')}")
}

#' Создать выходные директории
prepare_dirs <- function(cfg = ETL_CONFIG) {
  dirs <- c(cfg$output_dir, "logs")
  invisible(lapply(dirs, dir.create,
                   showWarnings = FALSE, recursive = TRUE))
}

# -----------------------------------------------------------------------------
# 2. EXTRACT — извлечение пакетов из PCAP через tshark
# -----------------------------------------------------------------------------

#' Список всех PCAP-files в директории
list_pcap_files <- function(pcap_dir) {
  files <- list.files(pcap_dir,
                      pattern = "\\.(pcap|pcapng|cap)$",
                      full.names = TRUE,
                      recursive = TRUE)
  if (length(files) == 0)
    stop(sprintf("PCAP files not found in: %s", pcap_dir))
  log_info("Found PCAP files: {length(files)}")
  files
}

#' Извлечь поля пакетов из одного PCAP-файла с помощью tshark
#' @param pcap_path  Путь к pcap-файлу
#' @param fields     Вектор имён tshark-полей
#' @return data.table с сырыми строками пакетов
extract_pcap <- function(pcap_path, fields = ETL_CONFIG$tshark_fields) {
  log_info("  Extracting: {basename(pcap_path)}")

  tshark_args <- c("-r", pcap_path, "-T", "fields")
  for (field in fields) {
    tshark_args <- c(tshark_args, "-e", field)
  }
  tshark_args <- c(
    tshark_args,
    "-E", "header=y",
    "-E", "separator=,",
    "-E", "quote=d",
    "-E", "occurrence=f"
  )

  raw_lines <- tryCatch(
    system2(ETL_CONFIG$tshark_bin, args = tshark_args, stdout = TRUE, stderr = TRUE),
    error = function(e) {
      log_error("tshark error for {basename(pcap_path)}: {e$message}")
      character(0)
    }
  )

  if (length(raw_lines) <= 1L) {
    log_warn("  File is empty or not processed: {basename(pcap_path)}")
    return(data.table())
  }

  dt <- tryCatch(
    fread(text = paste(raw_lines, collapse = "
"),
          header = TRUE, sep = ",", quote = '"',
          fill = TRUE, na.strings = c("", "NA")),
    error = function(e) {
      log_error("  CSV parsing error: {e$message}")
      data.table()
    }
  )

  dt[, source_file := basename(pcap_path)]
  log_info("  Extracted packets: {nrow(dt)}")
  dt
}

extract_all_pcap <- function(pcap_dir = ETL_CONFIG$pcap_dir,
                             n_workers = ETL_CONFIG$n_workers) {
  files <- list_pcap_files(pcap_dir)
  log_info("Extracting all PCAP files ({n_workers} workers)...")

  if (n_workers > 1L && requireNamespace("parallel", quietly = TRUE)) {
    cl <- parallel::makeCluster(n_workers)
    on.exit(parallel::stopCluster(cl))
    parallel::clusterExport(cl, c("extract_pcap", "ETL_CONFIG"), envir = environment())
    parallel::clusterEvalQ(cl, {
      library(data.table)
      library(logger)
      NULL
    })
    results <- parallel::parLapply(cl, files, extract_pcap)
  } else {
    results <- lapply(files, extract_pcap)
  }

  dt <- rbindlist(results, fill = TRUE, use.names = TRUE)
  if (nrow(dt) == 0L) {
    stop("No packets extracted from PCAP files. Check tshark installation.")
  }
  log_info("Total extracted packets: {nrow(dt)}")
  dt
}

standardize_columns <- function(dt) {
  if (nrow(dt) == 0L) {
    return(dt)
  }

  # Standardize column names
  old_names <- names(dt)
  new_names <- str_replace_all(old_names, "\\.", "_")
  setnames(dt, old_names, new_names)

  # ?????????? TCP/U  DP ports to single src_port / dst_port
  if ("tcp_srcport" %in% names(dt) && "udp_srcport" %in% names(dt)) {
    dt[, src_port := fcoalesce(
      suppressWarnings(as.integer(tcp_srcport)),
      suppressWarnings(as.integer(udp_srcport))
    )]
    dt[, dst_port := fcoalesce(
      suppressWarnings(as.integer(tcp_dstport)),
      suppressWarnings(as.integer(udp_dstport))
    )]
    dt[, c("tcp_srcport","tcp_dstport","udp_srcport","udp_dstport") := NULL]
  }

  dt
}

cast_types <- function(dt) {
  # Временная метка
  if ("frame_time_epoch" %in% names(dt))
    dt[, ts := as.numeric(frame_time_epoch)]

  # Числовые поля
  num_cols <- c("frame_len", "ip_ttl", "tcp_window_size_value",
                "tcp_analysis_ack_rtt", "icmp_type", "ip_proto")
  for (col in intersect(num_cols, names(dt)))
    set(dt, j = col, value = suppressWarnings(as.numeric(dt[[col]])))

  # Флаги TCP как integer
  if ("tcp_flags" %in% names(dt))
    dt[, tcp_flags := suppressWarnings(strtoi(tcp_flags, 16L))]

  dt
}

#' Сформировать 5-кортеж потока (flow key)
make_flow_key <- function(dt) {
  required_cols <- c("ip_src", "ip_dst", "src_port", "dst_port", "ip_proto")
  missing_cols <- setdiff(required_cols, names(dt))
  if (length(missing_cols) > 0) {
    stop(sprintf("Missing columns in extract(): %s",
                 paste(missing_cols, collapse = ", ")))
  }

  dt[, flow_id := paste(
    pmin(ip_src, ip_dst),
    pmax(ip_src, ip_dst),
    pmin(src_port, dst_port, na.rm = TRUE),
    pmax(src_port, dst_port, na.rm = TRUE),
    ip_proto,
    sep = "_"
  )]
  dt
}

safe_min <- function(x) {
  if (all(is.na(x))) NA_real_ else min(x, na.rm = TRUE)
}

safe_max <- function(x) {
  if (all(is.na(x))) NA_real_ else max(x, na.rm = TRUE)
}

aggregate_flows <- function(dt, timeout_sec = ETL_CONFIG$flow_timeout_sec) {
  log_info("Aggregating packets into flows (timeout={timeout_sec}s)...")

  setorder(dt, flow_id, ts)

  # Разметка сессий по таймауту (delta между пакетами внутри потока)
  dt[, delta_t := ts - shift(ts, 1L, fill = NA), by = flow_id]
  dt[, new_session := is.na(delta_t) | delta_t > timeout_sec]
  dt[, session_id := paste0(flow_id, "_", cumsum(new_session)), by = flow_id]

  flows <- dt[, .(
    # --- Идентификаторы ---
    src_ip        = ip_src[1L],
    dst_ip        = ip_dst[1L],
    src_port      = src_port[1L],
    dst_port      = dst_port[1L],
    proto         = ip_proto[1L],

    # --- Временные характеристики ---
    flow_start    = min(ts, na.rm = TRUE),
    flow_end      = max(ts, na.rm = TRUE),
    duration      = max(ts, na.rm = TRUE) - min(ts, na.rm = TRUE),

    # --- Объём трафика ---
    pkt_count     = .N,
    byte_count    = sum(frame_len, na.rm = TRUE),
    mean_pkt_len  = mean(frame_len, na.rm = TRUE),
    min_pkt_len   = safe_min(frame_len),
    max_pkt_len   = safe_max(frame_len),
    std_pkt_len   = sd(frame_len, na.rm = TRUE),

    # --- Скоростные признаки ---
    pkt_rate      = .N / pmax(max(ts, na.rm=TRUE) - min(ts, na.rm=TRUE), 1e-9),
    byte_rate     = sum(frame_len, na.rm=TRUE) /
                      pmax(max(ts, na.rm=TRUE) - min(ts, na.rm=TRUE), 1e-9),

    # --- TTL ---
    mean_ttl      = mean(ip_ttl, na.rm = TRUE),
    min_ttl       = safe_min(ip_ttl),

    # --- TCP-специфичные ---
    mean_win_size = mean(tcp_window_size_value, na.rm = TRUE),
    mean_ack_rtt  = mean(tcp_analysis_ack_rtt, na.rm = TRUE),

    # TCP-флаги (агрегируем побитовым OR)
    tcp_flags_agg = {
      flags <- na.omit(tcp_flags)
      if (length(flags) == 0L) NA_integer_ else as.integer(Reduce(bitwOr, flags))
    },

    # Наличие конкретных флагов
    has_syn       = as.integer(any(bitwAnd(tcp_flags, 0x02L) > 0, na.rm=TRUE)),
    has_fin       = as.integer(any(bitwAnd(tcp_flags, 0x01L) > 0, na.rm=TRUE)),
    has_rst       = as.integer(any(bitwAnd(tcp_flags, 0x04L) > 0, na.rm=TRUE)),
    has_psh       = as.integer(any(bitwAnd(tcp_flags, 0x08L) > 0, na.rm=TRUE)),
    has_ack       = as.integer(any(bitwAnd(tcp_flags, 0x10L) > 0, na.rm=TRUE)),

    # --- ICMP ---
    icmp_type_mode = if (all(is.na(icmp_type))) NA_integer_
                     else as.integer(names(which.max(table(icmp_type)))),

    # --- Межпакетные интервалы (IAT) ---
    mean_iat      = mean(delta_t, na.rm = TRUE),
    std_iat       = sd(delta_t, na.rm = TRUE),
    min_iat       = safe_min(delta_t),
    max_iat       = safe_max(delta_t),

    # --- Прикладной уровень ---
    has_dns       = as.integer(any(!is.na(dns_qry_name))),
    has_http      = as.integer(any(!is.na(http_request_method))),
    has_mqtt      = as.integer(any(!is.na(mqtt_msgtype))),

    # --- Метаданные ---
    source_file   = source_file[1L]

  ), by = session_id]

  # Вычисляемые признаки (14 дополнительных)
  flows[, `:=`(
    pkt_per_byte     = pkt_count / pmax(byte_count, 1L),
    byte_per_sec_log = log1p(byte_rate),
    pkt_per_sec_log  = log1p(pkt_rate),
    duration_log     = log1p(duration),
    is_bidirectional = as.integer(has_ack > 0 & has_syn > 0),
    tcp_flag_entropy = {
      f <- c(has_syn, has_fin, has_rst, has_psh, has_ack)
      p <- f / pmax(sum(f), 1)
      -sum(p[p > 0] * log2(p[p > 0]))
    },
    iat_cv           = std_iat / pmax(mean_iat, 1e-9),  # коэффициент вариации IAT
    port_class_src   = classify_port(src_port),
    port_class_dst   = classify_port(dst_port),
    proto_name       = proto_to_name(proto),
    is_iot_proto     = as.integer(dst_port %in% c(1883L, 8883L, 5683L, 5684L)),
                       # MQTT / MQTT-TLS / CoAP / CoAP-DTLS
    scan_indicator   = as.integer(pkt_count <= 3L & duration < 1),
    flood_indicator  = as.integer(pkt_rate > 1000),
    exfil_indicator  = as.integer(byte_count > 1e6 & duration < 60)
  )]

  log_info("Flow records created: {nrow(flows)}")
  flows
}

#' Классификатор порта → категория
classify_port <- function(port) {
  dplyr::case_when(
    is.na(port)       ~ "unknown",
    port < 1024L      ~ "well_known",
    port < 49152L     ~ "registered",
    TRUE              ~ "dynamic"
  )
}

#' Протокол (номер) → имя
proto_to_name <- function(proto) {
  dplyr::case_when(
    proto == 6L   ~ "TCP",
    proto == 17L  ~ "UDP",
    proto == 1L   ~ "ICMP",
    proto == 58L  ~ "ICMPv6",
    is.na(proto)  ~ "Unknown",
    TRUE          ~ as.character(proto)
  )
}

# -----------------------------------------------------------------------------
# 4. LABELING — разметка потоков по категориям атак BoT-IoT
# -----------------------------------------------------------------------------

#' Разметить потоки на основе имени исходного файла (логика BoT-IoT)
#'
#' Датасет разбит по директориям/файлам по категориям атак.
#' Именование files: DDoS_*, DoS_*, Reconnaissance_*, Theft_*, Normal_*
label_flows <- function(flows) {
  log_info("Labeling flows...")

  flows[, label := dplyr::case_when(
    str_detect(tolower(source_file), "ddos")           ~ "DDoS",
    str_detect(tolower(source_file), "dos")            ~ "DoS",
    str_detect(tolower(source_file), "recon|scan")     ~ "Reconnaissance",
    str_detect(tolower(source_file), "theft|keylog|exfil") ~ "Theft",
    str_detect(tolower(source_file), "normal|benign")  ~ "Normal",
    TRUE                                               ~ "Unknown"
  )]

  # Бинарная метка для классификаторов
  flows[, is_attack := as.integer(label != "Normal")]

  label_dist <- flows[, .N, by = label][order(-N)]
  log_info("Label distribution:\n{paste(capture.output(print(label_dist)), collapse='\n')}")

  flows
}

# -----------------------------------------------------------------------------
# 5. CLEANING — очистка и валидация
# -----------------------------------------------------------------------------

#' Удалить выбросы и невалидные записи
clean_flows <- function(flows) {
  n_before <- nrow(flows)
  log_info("Cleaning data (before: {n_before} records)...")

  # Удалить строки без временной метки или IP
  flows <- flows[!is.na(flow_start) & !is.na(src_ip) & !is.na(dst_ip)]

  # Удалить потоки с отрицательной длительностью
  flows <- flows[duration >= 0]

  # Заменить NA в числовых столбцах медианой
  num_cols <- sapply(flows, is.numeric)
  for (col in names(flows)[num_cols]) {
    med <- median(flows[[col]], na.rm = TRUE)
    if (!is.na(med)) {
      set(flows, which(is.na(flows[[col]])), col, med)
    }
  }

  # Удалить константные столбцы (нулевая дисперсия)
  const_cols <- names(which(sapply(
    flows[, .SD, .SDcols = names(flows)[num_cols]],
    function(x) var(x, na.rm = TRUE) == 0
  )))
  if (length(const_cols) > 0) {
    log_info("Removing constant columns: {paste(const_cols, collapse=', ')}")
    flows[, (const_cols) := NULL]
  }

  log_info("Cleaning completed (after: {nrow(flows)} records, removed: {n_before - nrow(flows)})")
  flows
}

# -----------------------------------------------------------------------------
# 6. NORMALIZATION — Normalization числовых признаков
# -----------------------------------------------------------------------------

#' Нормализовать числовые признаки
#' @return list(flows = dt, scaler = list) — scaler сохраняется для инференса
normalize_features <- function(flows,
                               method = ETL_CONFIG$normalize_method,
                               exclude = c("session_id", "src_ip", "dst_ip",
                                           "proto_name", "port_class_src",
                                           "port_class_dst", "label",
                                           "is_attack", "source_file",
                                           "flow_start", "flow_end")) {
  log_info("Normalization: method={method}")

  num_cols <- setdiff(
    names(flows)[sapply(flows, is.numeric)],
    exclude
  )

  scaler <- list(method = method, params = list())

  flows_norm <- copy(flows)

  for (col in num_cols) {
    x <- flows_norm[[col]]
    if (all(is.na(x))) {
      scaler$params[[col]] <- list(all_na = TRUE)
      next
    }

    if (method == "min-max") {
      mn <- min(x, na.rm = TRUE)
      mx <- max(x, na.rm = TRUE)
      rng <- mx - mn
      scaler$params[[col]] <- list(min = mn, max = mx)
      set(flows_norm, j = col,
          value = if (rng == 0) rep(0, length(x)) else (x - mn) / rng)

    } else if (method == "z-score") {
      mu  <- mean(x, na.rm = TRUE)
      sig <- sd(x,   na.rm = TRUE)
      scaler$params[[col]] <- list(mean = mu, sd = sig)
      set(flows_norm, j = col,
          value = if (sig == 0) rep(0, length(x)) else (x - mu) / sig)
    }
  }

  list(flows = flows_norm, scaler = scaler)
}

# -----------------------------------------------------------------------------
# 7. SPLIT — разбивка на train / val / test со стратификацией
# -----------------------------------------------------------------------------

#' Стратифицированная разбивка по метке атаки
save_dataset <- function(dt,
                         dataset_name = "bot_iot_flows",
                         output_dir = ETL_CONFIG$output_dir) {
  out_base <- file.path(output_dir, dataset_name)

  parquet_path <- paste0(out_base, ".parquet")
  write_parquet(dt, parquet_path, compression = "snappy")
  log_info("Parquet: {parquet_path} ({nrow(dt)} records)")

  csv_path <- paste0(out_base, ".csv.gz")
  fwrite(dt, csv_path, compress = "gzip")
  log_info("CSV.gz: {csv_path}")
}

#' Сохранить параметры нормализации для последующего инференса
save_scaler <- function(scaler, output_dir = ETL_CONFIG$output_dir) {
  path <- file.path(output_dir, "scaler.rds")
  saveRDS(scaler, path)
  log_info("Scaler saved: {path}")
}

#' Сохранить итоговый ETL-отчет
save_report <- function(flows,
                        output_dir = ETL_CONFIG$output_dir,
                        normalize_method = ETL_CONFIG$normalize_method) {
  report <- data.table(
    n_records = nrow(flows),
    n_features = ncol(flows),
    normalize_method = normalize_method
  )

  if ("is_attack" %in% names(flows)) {
    report[, `:=`(
      n_attack = sum(flows$is_attack, na.rm = TRUE),
      n_normal = sum(!flows$is_attack, na.rm = TRUE),
      pct_attack = round(100 * mean(flows$is_attack, na.rm = TRUE), 2)
    )]
  }

  if ("label" %in% names(flows)) {
    label_dist <- flows[, .N, by = label][order(-N)]
    report[, label_distribution := paste(
      sprintf("%s:%s", label_dist$label, label_dist$N),
      collapse = "; "
    )]
  }

  path <- file.path(output_dir, "etl_report.csv")
  fwrite(report, path)
  log_info("ETL report saved: {path}")
  print(report)
}

# -----------------------------------------------------------------------------
# 8. MAIN PIPELINE
# -----------------------------------------------------------------------------

#' Запустить полный ETL-пайплайн
#'
#' @param pcap_dir Директория с PCAP-файлами (NULL = пропустить PCAP-извлечение)
#' @param csv_dir  Директория с CSV-файлами BoT-IoT (NULL = пропустить CSV-импорт)
#' @param cfg      Конфигурация ETL
#' @return list(flows, scaler)
run_etl <- function(pcap_dir = ETL_CONFIG$pcap_dir,
                    csv_dir  = ETL_CONFIG$csv_dir,
                    cfg      = ETL_CONFIG) {

  init_logger(cfg$log_file)
  check_dependencies()
  prepare_dirs(cfg)

  raw_dt <- if (!is.null(pcap_dir) && dir.exists(pcap_dir)) {
    log_info("Step 1/5: EXTRACT (PCAP -> packets)")
    extract_all_pcap(pcap_dir, cfg$n_workers)
  } else if (!is.null(csv_dir) && dir.exists(csv_dir)) {
    log_info("Step 1/5: EXTRACT (CSV -> data.table)")
    files <- list.files(csv_dir, pattern = "\\.csv(\\.gz)?$",
                        full.names = TRUE, recursive = TRUE)
    log_info("Found CSV-files: {length(files)}")
    rbindlist(lapply(files, fread, fill = TRUE), fill = TRUE, use.names = TRUE)
  } else {
    stop("Specify pcap_dir or csv_dir with original data.")
  }

  log_info("Step 2/5: TRANSFORM")

  if (!is.null(pcap_dir) && dir.exists(pcap_dir)) {
    raw_dt <- standardize_columns(raw_dt)
    raw_dt <- cast_types(raw_dt)
    raw_dt <- make_flow_key(raw_dt)
    flows  <- aggregate_flows(raw_dt, cfg$flow_timeout_sec)
  } else {
    flows <- raw_dt
    bot_iot_rename <- c(
      "pkSeqID"  = "session_id", "stime" = "flow_start", "ltime" = "flow_end",
      "dur"      = "duration",   "proto" = "proto_name",
      "saddr"    = "src_ip",     "daddr" = "dst_ip",
      "sport"    = "src_port",   "dport" = "dst_port",
      "pkts"     = "pkt_count",  "bytes" = "byte_count",
      "state"    = "tcp_state",  "category" = "label",
      "subcategory" = "sub_label"
    )
    present <- intersect(names(bot_iot_rename), names(flows))
    setnames(flows, present, bot_iot_rename[present])

    if ("label" %in% names(flows))
      flows[, is_attack := as.integer(tolower(label) != "normal")]
    if (!("source_file" %in% names(flows)))
      flows[, source_file := "csv_import"]
  }

  log_info("Step 3/5: CLEAN")
  flows <- clean_flows(flows)

  log_info("Step 4/5: NORMALIZE")
  norm_result <- normalize_features(flows, cfg$normalize_method)
  flows  <- norm_result$flows
  scaler <- norm_result$scaler
  save_scaler(scaler, cfg$output_dir)

  log_info("Step 5/5: LOAD")
  save_dataset(flows, output_dir = cfg$output_dir)
  save_report(flows,
              output_dir = cfg$output_dir,
              normalize_method = cfg$normalize_method)

  log_info("=== ETL completed successfully ===")
  invisible(list(flows = flows, scaler = scaler))
}

# -----------------------------------------------------------------------------
# 9. УТИЛИТЫ ДЛЯ ИНФЕРЕНСА — применение savedного scaler к новым данным
# -----------------------------------------------------------------------------

#' Применить savedный scaler к новому батчу
apply_scaler <- function(dt, scaler_path) {
  scaler <- readRDS(scaler_path)
  dt_out <- copy(dt)
  for (col in names(scaler$params)) {
    if (!col %in% names(dt_out)) next
    p <- scaler$params[[col]]
    if (scaler$method == "min-max") {
      rng <- p$max - p$min
      set(dt_out, j = col,
          value = if (rng == 0) rep(0, nrow(dt_out))
                  else (dt_out[[col]] - p$min) / rng)
    } else if (scaler$method == "z-score") {
      set(dt_out, j = col,
          value = if (p$sd == 0) rep(0, nrow(dt_out))
                  else (dt_out[[col]] - p$mean) / p$sd)
    }
  }
  dt_out
}

# -----------------------------------------------------------------------------
# 11. ТОЧКА ВХОДА (Starting из командной строки)
# -----------------------------------------------------------------------------

if (!interactive()) {
  args <- commandArgs(trailingOnly = TRUE)

  pcap_dir <- if (length(args) >= 1) args[1] else ETL_CONFIG$pcap_dir
  csv_dir  <- if (length(args) >= 2) args[2] else ETL_CONFIG$csv_dir

  cat(sprintf("▶ Starting BoT-IoT ETL\n  PCAP: %s\n  CSV:  %s\n",
              pcap_dir, csv_dir))

  tryCatch(
    run_etl(pcap_dir = pcap_dir, csv_dir = csv_dir),
    error = function(e) {
      cat(sprintf("ETL ERROR: %s\n", e$message))
      quit(status = 1L)
    }
  )
}






# =============================================================================
# === ENHANCED ML FEATURES (ADDED) ============================================
# =============================================================================

WINDOW_SIZE <- 60
FLOW_TIMEOUT <- 30

add_directional_features <- function(dt) {
  dt[, bytes_ratio := bytes_fwd / (bytes_bwd + 1)]
  dt[, packets_ratio := packets_fwd / (packets_bwd + 1)]
  dt
}

add_behavior_features <- function(dt) {
  dt[, window := floor(timestamp / WINDOW_SIZE)]

  stats <- dt[, .(
    conn_count = .N,
    unique_dst = uniqueN(ip.dst),
    unique_ports = uniqueN(tcp.dstport),
    mean_pkt_size = mean(frame.len)
  ), by = .(ip.src, window)]

  merge(dt, stats, by = c("ip.src", "window"), all.x = TRUE)
}

add_time_features <- function(dt) {
  setorder(dt, timestamp)
  dt[, iat := c(NA, diff(timestamp)), by = ip.src]
  dt[, iat_cv := sd(iat, na.rm=TRUE) / (mean(iat, na.rm=TRUE)+1e-6), by = ip.src]
  dt
}

clean_na_smart <- function(dt) {
  num_cols <- names(dt)[sapply(dt, is.numeric)]
  for (col in num_cols) {
    dt[is.na(get(col)), (col) := 0]
  }
  dt
}

normalize_split <- function(dt) {
  set.seed(42)
  idx <- sample(1:nrow(dt), 0.8*nrow(dt))

  train <- dt[idx]
  test  <- dt[-idx]

  num_cols <- names(train)[sapply(train, is.numeric)]

  scaler <- lapply(num_cols, function(col) {
    list(mean=mean(train[[col]]), sd=sd(train[[col]])+1e-6)
  })
  names(scaler) <- num_cols

  for (col in num_cols) {
    train[[col]] <- (train[[col]] - scaler[[col]]$mean) / scaler[[col]]$sd
    test[[col]]  <- (test[[col]]  - scaler[[col]]$mean) / scaler[[col]]$sd
  }

  list(train=train, test=test, scaler=scaler)
}

# =============================================================================
# === PIPELINE EXTENSION ======================================================
# =============================================================================

enhanced_feature_pipeline <- function(dt) {
  log_info("Добавление расширенных ML-признаков")

  dt <- add_directional_features(dt)
  dt <- add_behavior_features(dt)
  dt <- add_time_features(dt)
  dt <- clean_na_smart(dt)

  norm <- normalize_split(dt)

  return(norm)
}

