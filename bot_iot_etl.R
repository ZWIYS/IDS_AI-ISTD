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

suppressPackageStartupMessages({
  library(data.table)
  library(dplyr)
  library(tidyr)
  library(stringr)
  library(lubridate)
  library(arrow)       # запись в Parquet
  library(logger)      # структурированное логирование
  library(R.utils)     # системные утилиты
})

# -----------------------------------------------------------------------------
# 0. Конфигурация
# -----------------------------------------------------------------------------

ETL_CONFIG <- list(
  # Пути
  pcap_dir      = "data/raw/pcap",        # директория с .pcap/.pcapng файлами
  csv_dir       = "data/raw/csv",         # директория с исходными CSV (опционально)
  output_dir    = "data/processed",       # куда сохранять результат
  log_file      = "logs/etl_bot_iot.log",

  # Параметры tshark
  tshark_bin    = "tshark",
  tshark_fields = c(                      # поля для извлечения (--e флаги)
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

  # Параметры flow-агрегации
  flow_timeout_sec = 120,   # таймаут неактивности потока (секунды)

  # Метки атак BoT-IoT (категории из оригинального датасета)
  attack_categories = c(
    "DDoS", "DoS", "Reconnaissance",
    "Theft",          # keylogging + data exfiltration
    "Normal"
  ),

  # Нормализация
  normalize_method  = "min-max",  # "min-max" | "z-score" | "none"

  # Разбивка выборки
  train_ratio = 0.70,
  val_ratio   = 0.15,
  test_ratio  = 0.15,

  # Воспроизводимость
  random_seed = 42L,

  # Параллелизм
  n_workers = max(1L, parallel::detectCores() - 1L)
)

# -----------------------------------------------------------------------------
# 1. Утилиты
# -----------------------------------------------------------------------------

#' Инициализировать систему логирования
init_logger <- function(log_file) {
  dir.create(dirname(log_file), showWarnings = FALSE, recursive = TRUE)
  log_appender(appender_tee(log_file))
  log_threshold(INFO)
  log_formatter(formatter_glue_or_sprintf)
  log_info("=== BoT-IoT ETL инициализирован ===")
}

#' Проверить наличие системных зависимостей
check_dependencies <- function() {
  log_info("Проверка системных зависимостей...")
  bins <- c(ETL_CONFIG$tshark_bin)
  missing <- bins[!nzchar(Sys.which(bins))]
  if (length(missing) > 0) {
    stop(sprintf("Не найдены системные утилиты: %s\n  Установите: sudo apt-get install tshark",
                 paste(missing, collapse = ", ")))
  }
  log_info("Зависимости OK: {paste(bins, collapse=', ')}")
}

#' Создать выходные директории
prepare_dirs <- function(cfg = ETL_CONFIG) {
  dirs <- c(cfg$output_dir,
            file.path(cfg$output_dir, "train"),
            file.path(cfg$output_dir, "val"),
            file.path(cfg$output_dir, "test"),
            "logs")
  invisible(lapply(dirs, dir.create,
                   showWarnings = FALSE, recursive = TRUE))
}

# -----------------------------------------------------------------------------
# 2. EXTRACT — извлечение пакетов из PCAP через tshark
# -----------------------------------------------------------------------------

#' Список всех PCAP-файлов в директории
list_pcap_files <- function(pcap_dir) {
  files <- list.files(pcap_dir,
                      pattern = "\\.(pcap|pcapng|cap)$",
                      full.names = TRUE,
                      recursive = TRUE)
  if (length(files) == 0)
    stop(sprintf("PCAP-файлы не найдены в: %s", pcap_dir))
  log_info("Найдено PCAP-файлов: {length(files)}")
  files
}

#' Извлечь поля пакетов из одного PCAP-файла с помощью tshark
#' @param pcap_path  Путь к pcap-файлу
#' @param fields     Вектор имён tshark-полей
#' @return data.table с сырыми строками пакетов
extract_pcap <- function(pcap_path, fields = ETL_CONFIG$tshark_fields) {
  log_info("  Извлечение: {basename(pcap_path)}")

  field_args <- paste(
    sapply(fields, function(f) sprintf("-e %s", f)),
    collapse = " "
  )

  cmd <- sprintf(
    "%s -r %s -T fields %s -E header=y -E separator=, -E quote=d -E occurrence=f 2>/dev/null",
    ETL_CONFIG$tshark_bin,
    shQuote(pcap_path),
    field_args
  )

  raw_lines <- tryCatch(
    system(cmd, intern = TRUE),
    error = function(e) {
      log_error("Ошибка tshark для {basename(pcap_path)}: {e$message}")
      character(0)
    }
  )

  if (length(raw_lines) <= 1L) {
    log_warn("  Файл пуст или не обработан: {basename(pcap_path)}")
    return(data.table())
  }

  # Парсинг CSV-вывода tshark
  dt <- tryCatch(
    fread(text = paste(raw_lines, collapse = "\n"),
          header = TRUE, sep = ",", quote = '"',
          fill = TRUE, na.strings = c("", "NA")),
    error = function(e) {
      log_error("  Парсинг CSV завершился ошибкой: {e$message}")
      data.table()
    }
  )

  dt[, source_file := basename(pcap_path)]
  log_info("  Извлечено пакетов: {nrow(dt)}")
  dt
}

#' Пакетное извлечение из всех PCAP (с параллелизмом)
extract_all_pcap <- function(pcap_dir = ETL_CONFIG$pcap_dir,
                             n_workers = ETL_CONFIG$n_workers) {
  files <- list_pcap_files(pcap_dir)
  log_info("Начало пакетного извлечения ({n_workers} воркеров)...")

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
  log_info("Итого сырых пакетов: {nrow(dt)}")
  dt
}

# -----------------------------------------------------------------------------
# 3. TRANSFORM — преобразование пакетов в flow-признаки
# -----------------------------------------------------------------------------

#' Унифицировать имена столбцов после tshark
standardize_columns <- function(dt) {
  # Базовое переименование: убираем точки в именах
  old_names <- names(dt)
  new_names <- str_replace_all(old_names, "\\.", "_")
  setnames(dt, old_names, new_names)

  # Объединяем TCP/UDP порты в единые поля src_port / dst_port
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

#' Приведение типов сырых столбцов
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

#' Агрегировать пакеты → записи потоков
#'
#' Воспроизводит 29 оригинальных признаков BoT-IoT (Argus-совместимый набор)
#' плюс 14 вычисляемых признаков.
aggregate_flows <- function(dt, timeout_sec = ETL_CONFIG$flow_timeout_sec) {
  log_info("Агрегация пакетов в потоки (timeout={timeout_sec}s)...")

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
    min_pkt_len   = min(frame_len, na.rm = TRUE),
    max_pkt_len   = max(frame_len, na.rm = TRUE),
    std_pkt_len   = sd(frame_len, na.rm = TRUE),

    # --- Скоростные признаки ---
    pkt_rate      = .N / pmax(max(ts, na.rm=TRUE) - min(ts, na.rm=TRUE), 1e-9),
    byte_rate     = sum(frame_len, na.rm=TRUE) /
                      pmax(max(ts, na.rm=TRUE) - min(ts, na.rm=TRUE), 1e-9),

    # --- TTL ---
    mean_ttl      = mean(ip_ttl, na.rm = TRUE),
    min_ttl       = min(ip_ttl, na.rm = TRUE),

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
    min_iat       = min(delta_t, na.rm = TRUE),
    max_iat       = max(delta_t, na.rm = TRUE),

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

  log_info("Сформировано flow-записей: {nrow(flows)}")
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
#' Именование файлов: DDoS_*, DoS_*, Reconnaissance_*, Theft_*, Normal_*
label_flows <- function(flows) {
  log_info("Разметка потоков...")

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
  log_info("Распределение меток:\n{paste(capture.output(print(label_dist)), collapse='\n')}")

  flows
}

# -----------------------------------------------------------------------------
# 5. CLEANING — очистка и валидация
# -----------------------------------------------------------------------------

#' Удалить выбросы и невалидные записи
clean_flows <- function(flows) {
  n_before <- nrow(flows)
  log_info("Очистка данных (до: {n_before} записей)...")

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
    log_info("Удаление константных столбцов: {paste(const_cols, collapse=', ')}")
    flows[, (const_cols) := NULL]
  }

  log_info("Очистка завершена (после: {nrow(flows)} записей, удалено: {n_before - nrow(flows)})")
  flows
}

# -----------------------------------------------------------------------------
# 6. NORMALIZATION — нормализация числовых признаков
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
  log_info("Нормализация: метод={method}")

  num_cols <- setdiff(
    names(flows)[sapply(flows, is.numeric)],
    exclude
  )

  scaler <- list(method = method, params = list())

  flows_norm <- copy(flows)

  for (col in num_cols) {
    x <- flows_norm[[col]]
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
split_dataset <- function(flows,
                          train_r = ETL_CONFIG$train_ratio,
                          val_r   = ETL_CONFIG$val_ratio,
                          seed    = ETL_CONFIG$random_seed) {
  set.seed(seed)
  log_info("Разбивка датасета: train={train_r}, val={val_r}, test={1-train_r-val_r}")

  flows[, split_idx := {
    n     <- .N
    ord   <- sample(n)
    n_tr  <- floor(n * train_r)
    n_val <- floor(n * val_r)
    res   <- character(n)
    res[ord[seq_len(n_tr)]]                          <- "train"
    res[ord[seq(n_tr + 1, n_tr + n_val)]]           <- "val"
    res[ord[seq(n_tr + n_val + 1, n)]]              <- "test"
    res
  }, by = label]

  list(
    train = flows[split_idx == "train"][, split_idx := NULL],
    val   = flows[split_idx == "val"  ][, split_idx := NULL],
    test  = flows[split_idx == "test" ][, split_idx := NULL]
  )
}

# -----------------------------------------------------------------------------
# 8. LOAD — сохранение результатов
# -----------------------------------------------------------------------------

#' Сохранить датасет в Parquet + CSV
save_split <- function(dt, name, output_dir = ETL_CONFIG$output_dir) {
  out_base <- file.path(output_dir, name,
                        sprintf("bot_iot_%s", name))

  # Parquet (эффективно для больших объёмов)
  parquet_path <- paste0(out_base, ".parquet")
  write_parquet(dt, parquet_path, compression = "snappy")
  log_info("  [{name}] Parquet: {parquet_path} ({nrow(dt)} записей)")

  # CSV (совместимость)
  csv_path <- paste0(out_base, ".csv.gz")
  fwrite(dt, csv_path, compress = "gzip")
  log_info("  [{name}] CSV.gz: {csv_path}")
}

#' Сохранить параметры нормализации (для инференса)
save_scaler <- function(scaler, output_dir = ETL_CONFIG$output_dir) {
  path <- file.path(output_dir, "scaler.rds")
  saveRDS(scaler, path)
  log_info("Scaler сохранён: {path}")
}

#' Сохранить итоговый отчёт об обработке
save_report <- function(splits, output_dir = ETL_CONFIG$output_dir) {
  report <- rbindlist(lapply(names(splits), function(s) {
    dt <- splits[[s]]
    data.table(
      split     = s,
      n_records = nrow(dt),
      n_attack  = sum(dt$is_attack),
      n_normal  = sum(!dt$is_attack),
      pct_attack = round(100 * mean(dt$is_attack), 2)
    )
  }))

  path <- file.path(output_dir, "etl_report.csv")
  fwrite(report, path)
  log_info("Отчёт сохранён: {path}")
  print(report)
}

# -----------------------------------------------------------------------------
# 9. MAIN PIPELINE
# -----------------------------------------------------------------------------

#' Запустить полный ETL-пайплайн
#'
#' @param pcap_dir  Директория с PCAP-файлами (NULL = пропустить шаг Extract)
#' @param csv_dir   Директория с готовыми CSV BoT-IoT (NULL = пропустить)
#' @param cfg       Конфигурация (список ETL_CONFIG)
#' @return list(splits, scaler)
run_etl <- function(pcap_dir = ETL_CONFIG$pcap_dir,
                    csv_dir  = ETL_CONFIG$csv_dir,
                    cfg      = ETL_CONFIG) {

  init_logger(cfg$log_file)
  check_dependencies()
  prepare_dirs(cfg)

  # ── EXTRACT ──────────────────────────────────────────────────────────────
  raw_dt <- if (!is.null(pcap_dir) && dir.exists(pcap_dir)) {
    log_info("▶ Шаг 1/5: EXTRACT (PCAP → пакеты)")
    extract_all_pcap(pcap_dir, cfg$n_workers)
  } else if (!is.null(csv_dir) && dir.exists(csv_dir)) {
    log_info("▶ Шаг 1/5: EXTRACT (CSV BoT-IoT → data.table)")
    files <- list.files(csv_dir, pattern = "\\.csv(\\.gz)?$",
                        full.names = TRUE, recursive = TRUE)
    log_info("  Найдено CSV: {length(files)}")
    rbindlist(lapply(files, fread, fill = TRUE), fill = TRUE, use.names = TRUE)
  } else {
    stop("Укажите pcap_dir или csv_dir с исходными данными.")
  }

  # ── TRANSFORM ─────────────────────────────────────────────────────────────
  log_info("▶ Шаг 2/5: TRANSFORM")

  if (!is.null(pcap_dir) && dir.exists(pcap_dir)) {
    # Путь PCAP: стандартизация → агрегация flow
    raw_dt <- standardize_columns(raw_dt)
    raw_dt <- cast_types(raw_dt)
    raw_dt <- make_flow_key(raw_dt)
    flows  <- aggregate_flows(raw_dt, cfg$flow_timeout_sec)
  } else {
    # Путь CSV BoT-IoT: данные уже в формате flow — лёгкая трансформация
    flows <- raw_dt
    # Переименование стандартных колонок датасета BoT-IoT CSV (если нужно)
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

    # Бинарная метка
    if ("label" %in% names(flows))
      flows[, is_attack := as.integer(tolower(label) != "normal")]
    if (!"source_file" %in% names(flows))
      flows[, source_file := "csv_import"]
  }

  # ── LABELING ──────────────────────────────────────────────────────────────
  if (!"label" %in% names(flows))
    flows <- label_flows(flows)

  # ── CLEANING ──────────────────────────────────────────────────────────────
  log_info("▶ Шаг 3/5: CLEAN")
  flows <- clean_flows(flows)

  # ── NORMALIZE ─────────────────────────────────────────────────────────────
  log_info("▶ Шаг 4/5: NORMALIZE")
  norm_result <- normalize_features(flows, cfg$normalize_method)
  flows  <- norm_result$flows
  scaler <- norm_result$scaler
  save_scaler(scaler, cfg$output_dir)

  # ── LOAD ──────────────────────────────────────────────────────────────────
  log_info("▶ Шаг 5/5: LOAD")
  splits <- split_dataset(flows)

  invisible(lapply(names(splits),
                   function(s) save_split(splits[[s]], s, cfg$output_dir)))

  save_report(splits, cfg$output_dir)

  log_info("=== ETL завершён успешно ===")
  invisible(list(splits = splits, scaler = scaler))
}

# -----------------------------------------------------------------------------
# 10. УТИЛИТЫ ДЛЯ ИНФЕРЕНСА — применить сохранённый scaler к новым данным
# -----------------------------------------------------------------------------

#' Применить сохранённый scaler к новому батчу
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
# 11. ТОЧКА ВХОДА (запуск из командной строки)
# -----------------------------------------------------------------------------

if (!interactive()) {
  args <- commandArgs(trailingOnly = TRUE)

  pcap_dir <- if (length(args) >= 1) args[1] else ETL_CONFIG$pcap_dir
  csv_dir  <- if (length(args) >= 2) args[2] else ETL_CONFIG$csv_dir

  cat(sprintf("▶ Запуск BoT-IoT ETL\n  PCAP: %s\n  CSV:  %s\n",
              pcap_dir, csv_dir))

  tryCatch(
    run_etl(pcap_dir = pcap_dir, csv_dir = csv_dir),
    error = function(e) {
      cat(sprintf("ОШИБКА ETL: %s\n", e$message))
      quit(status = 1L)
    }
  )
}
