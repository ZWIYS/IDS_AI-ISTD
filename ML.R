# ============================================================================
#  ОБНАРУЖЕНИЕ ВТОРЖЕНИЙ В IoT-СЕТИ С ИСПОЛЬЗОВАНИЕМ ISOLATION FOREST
# ============================================================================
# Версия: Полная с обработкой пропусков
# ============================================================================

# ----------------------------------------------------------------------------
# 1. ПОДКЛЮЧЕНИЕ БИБЛИОТЕК
# ----------------------------------------------------------------------------

# Установка (раскомментировать при первом запуске):
# install.packages(c("arrow", "dplyr", "tidyr", "ggplot2", "stringr", "isotree"))

library(arrow)        # Чтение Parquet файлов
library(dplyr)        # Манипуляция данными
library(tidyr)        # Очистка данных
library(ggplot2)      # Визуализация
library(stringr)      # Работа со строками
library(isotree)      # Isolation Forest (современная реализация)

# ----------------------------------------------------------------------------
# 2. ЗАГРУЗКА ДАННЫХ ИЗ PARQUET
# ----------------------------------------------------------------------------

cat("\n", paste(rep("=", 80), collapse = ""), "\n", sep = "")
cat("=== 1. ЗАГРУЗКА ДАННЫХ ИЗ PARQUET ===\n")
cat(paste(rep("=", 80), collapse = ""), "\n\n", sep = "")

# Проверяем существование файла
if (!file.exists("iotids_train.parquet")) {
  stop("ОШИБКА: Файл 'iotids_train.parquet' не найден в текущей директории!\n",
       "Текущая директория: ", getwd())
}

# Загружаем данные
iot_data <- read_parquet("iotids_train.parquet")

cat(" Данные успешно загружены!\n")
cat(" Количество строк (сессий):", nrow(iot_data), "\n")
cat(" Количество признаков:", ncol(iot_data), "\n")
cat(" Имена колонок:", paste(colnames(iot_data)[1:min(10, ncol(iot_data))], collapse = ", "), 
    ifelse(ncol(iot_data) > 10, "...", ""), "\n\n")

# ----------------------------------------------------------------------------
# 3. ПОДГОТОВКА ПРИЗНАКОВ С ЗАМЕНОЙ ПРОПУСКОВ
# ----------------------------------------------------------------------------

cat("=== 2. ПОДГОТОВКА ПРИЗНАКОВ ===\n\n")

# Вспомогательная функция для проверки наличия колонки
has_column <- function(data, col_name) {
  return(col_name %in% colnames(data))
}

prepare_features <- function(data) {
  
  cat("  Преобразую признаки...\n")
  
  # Создаём копию данных
  prepared <- data
  
  # ----- 1. Базовые метрики соединения -----
  if (has_column(data, "duration")) prepared$duration <- as.numeric(prepared$duration)
  if (has_column(data, "orig_bytes")) prepared$orig_bytes <- as.numeric(prepared$orig_bytes)
  if (has_column(data, "resp_bytes")) prepared$resp_bytes <- as.numeric(prepared$resp_bytes)
  if (has_column(data, "missed_bytes")) prepared$missed_bytes <- as.numeric(prepared$missed_bytes)
  
  # Категориальные признаки
  if (has_column(data, "proto")) prepared$proto <- as.factor(prepared$proto)
  if (has_column(data, "conn_state")) prepared$conn_state <- as.factor(prepared$conn_state)
  if (has_column(data, "service")) prepared$service <- as.factor(prepared$service)
  if (has_column(data, "history")) prepared$history <- as.character(prepared$history)
  
  # Длина истории как дополнительный числовой признак
  if (has_column(data, "history")) {
    prepared$history_length <- nchar(as.character(prepared$history))
  } else {
    prepared$history_length <- 0
  }
  
  # ----- 2. HTTP признаки -----
  prepared$uri_length <- ifelse(has_column(data, "uri_length") & !is.na(data$uri_length), 
                                as.numeric(data$uri_length), 0)
  prepared$ua_length <- ifelse(has_column(data, "ua_length") & !is.na(data$ua_length), 
                               as.numeric(data$ua_length), 0)
  prepared$http_status_code <- ifelse(has_column(data, "http_status_code") & !is.na(data$http_status_code), 
                                      as.numeric(data$http_status_code), 0)
  prepared$http_method <- ifelse(has_column(data, "http_method") & !is.na(data$http_method) & data$http_method != "NA",
                                 as.factor(data$http_method), factor(NA))
  
  # ----- 3. DNS признаки -----
  prepared$query_length <- ifelse(has_column(data, "query_length") & !is.na(data$query_length), 
                                  as.numeric(data$query_length), 0)
  prepared$query_entropy <- ifelse(has_column(data, "query_entropy") & !is.na(data$query_entropy), 
                                   as.numeric(data$query_entropy), 0)
  prepared$num_labels <- ifelse(has_column(data, "num_labels") & !is.na(data$num_labels), 
                                as.numeric(data$num_labels), 0)
  
  # ----- 4. Поведенческие признаки (агрегации) -----
  if (has_column(data, "conn_count_5min_src")) {
    prepared$conn_count_5min <- as.numeric(prepared$conn_count_5min_src)
  } else if (has_column(data, "conn_count_5min")) {
    prepared$conn_count_5min <- as.numeric(prepared$conn_count_5min)
  } else {
    prepared$conn_count_5min <- 0
  }
  
  if (has_column(data, "dest_port_distinct_count_src")) {
    prepared$dest_port_distinct <- as.numeric(prepared$dest_port_distinct_count_src)
  } else if (has_column(data, "dest_port_distinct")) {
    prepared$dest_port_distinct <- as.numeric(prepared$dest_port_distinct)
  } else {
    prepared$dest_port_distinct <- 0
  }
  
  if (has_column(data, "unique_dst_ip_src")) {
    prepared$unique_dst_ip <- as.numeric(prepared$unique_dst_ip_src)
  } else if (has_column(data, "unique_dst_ip")) {
    prepared$unique_dst_ip <- as.numeric(prepared$unique_dst_ip)
  } else {
    prepared$unique_dst_ip <- 0
  }
  
  if (has_column(data, "data_volume_pct_change")) {
    prepared$data_volume_change <- as.numeric(prepared$data_volume_pct_change)
  } else {
    prepared$data_volume_change <- 0
  }
  
  # ----- 5. SSL признаки -----
  if (has_column(data, "ssl_sni_length")) {
    prepared$ssl_sni_length <- ifelse(is.na(prepared$ssl_sni_length), 0, as.numeric(prepared$ssl_sni_length))
  } else {
    prepared$ssl_sni_length <- 0
  }
  
  if (has_column(data, "ssl_sni_entropy")) {
    prepared$ssl_sni_entropy <- ifelse(is.na(prepared$ssl_sni_entropy), 0, as.numeric(prepared$ssl_sni_entropy))
  } else {
    prepared$ssl_sni_entropy <- 0
  }
  
  # ----- Формируем финальный набор признаков -----
  # Числовые признаки
  numeric_features <- c(
    "duration", "orig_bytes", "resp_bytes", "missed_bytes",
    "history_length", "uri_length", "ua_length", "http_status_code",
    "query_length", "query_entropy", "num_labels",
    "conn_count_5min", "dest_port_distinct", "unique_dst_ip",
    "data_volume_change", "ssl_sni_length", "ssl_sni_entropy"
  )
  
  # Категориальные признаки
  categorical_features <- c()
  if (has_column(prepared, "proto")) categorical_features <- c(categorical_features, "proto")
  if (has_column(prepared, "conn_state")) categorical_features <- c(categorical_features, "conn_state")
  if (has_column(prepared, "service")) categorical_features <- c(categorical_features, "service")
  if (has_column(prepared, "http_method") && sum(!is.na(prepared$http_method)) > 0) {
    categorical_features <- c(categorical_features, "http_method")
  }
  
  # Собираем все признаки
  all_features <- c(numeric_features, categorical_features)
  
  # Проверяем, какие колонки реально существуют
  existing_features <- all_features[all_features %in% colnames(prepared)]
  missing_features <- setdiff(all_features, existing_features)
  
  if (length(missing_features) > 0) {
    cat("   Предупреждение: Отсутствуют признаки:", paste(missing_features, collapse = ", "), "\n")
    cat("     Они будут заполнены значениями по умолчанию.\n")
    for (col in missing_features) {
      prepared[[col]] <- 0
    }
  }
  
  # Выбираем только нужные колонки
  features <- prepared[, all_features]
  
  # ЗАМЕНЯЕМ NA И INF НА 0 (для числовых признаков)
  for (col in numeric_features) {
    if (col %in% colnames(features)) {
      features[[col]][is.na(features[[col]])] <- 0
      features[[col]][is.infinite(features[[col]])] <- 0
    }
  }
  
  cat("  Готово", ncol(features), "признаков (", 
      length(numeric_features[numeric_features %in% existing_features]), " числовых, ",
      length(categorical_features[categorical_features %in% existing_features]), " категориальных)\n", sep = "")
  
  attr(prepared, "features") <- features
  return(prepared)
}

# Подготавливаем данные
prepared_data <- prepare_features(iot_data)
model_features <- attr(prepared_data, "features")

cat("\n")
cat(" Статистика по подготовленным признакам:\n")
cat("   - Числовых признаков:", sum(sapply(model_features, is.numeric)), "\n")
cat("   - Категориальных признаков:", sum(sapply(model_features, is.factor)), "\n")
cat("   - Полное пропусков после обработки:", sum(is.na(model_features)), "\n\n")

# ----------------------------------------------------------------------------
# 4. ОБУЧЕНИЕ ISOLATION FOREST (через пакет isotree)
# ----------------------------------------------------------------------------

cat("=== 3. ОБУЧЕНИЕ ISOLATION FOREST ===\n\n")

# Проверяем, что пакет isotree загружен
if (!require(isotree, quietly = TRUE)) {
  stop("\n ОШИБКА: Пакет 'isotree' не загружен!\n",
       "Установите его командой: install.packages('isotree')\n",
       "Затем перезапустите R и выполните library(isotree)\n")
}

# Проверяем, что функция isolation_forest существует
if (!exists("isolation.forest")) {
  stop("\n ОШИБКА: Функция 'isolation_forest' не найдена!\n",
       "Убедитесь, что пакет 'isotree' установлен и загружен.\n",
       "Выполните: library(isotree)\n")
}

cat("  Пакет isotree загружен, функция isolation_forest доступна\n\n")

# Определяем размер подвыборки
sample_size <- min(256, nrow(model_features))
cat("   Размер выборки для обучения:", nrow(model_features), "сессий\n")
cat("   Размер подвыборки для каждого дерева:", sample_size, "\n")
cat("   Количество деревьев: 100\n\n")

# Обучаем модель Isolation Forest
set.seed(42)

cat("   Запуск обучения...\n")

# Для isotree важно: категориальные признаки должны быть factor
# Убеждаемся, что категориальные признаки в правильном формате
for (col in names(model_features)) {
  if (is.character(model_features[[col]])) {
    model_features[[col]] <- as.factor(model_features[[col]])
  }
}

model <- isolation.forest(
  model_features,
  ntrees = 100,                      # Количество деревьев
  sample_size = sample_size,         # Размер подвыборки
  max_depth = 50,                    # Максимальная глубина
  nthreads = 4,                      # Параллельные потоки
  seed = 42,
  missing_action = "divide"            # Игнорируем пропуски (хотя мы уже заменили их на 0)
)

cat("  Модель успешно обучена!\n")
cat("     - Тип модели: Isolation Forest\n")
cat("     - Количество деревьев:", model$ntrees, "\n")
cat("     - Размер подвыборки:", model$sample_size, "\n\n")

# ----------------------------------------------------------------------------
# 5. ПОЛУЧЕНИЕ ОЦЕНОК АНОМАЛЬНОСТИ
# ----------------------------------------------------------------------------

cat("=== 4. ВЫЧИСЛЕНИЕ ОЦЕНОК АНОМАЛЬНОСТИ ===\n\n")

cat("   Расчёт оценок для всех сессий...\n")

# Получаем оценки аномальности (0-1, где 1 = наиболее аномальная)
anomaly_scores <- predict(model, model_features, type = "score")

cat("  Оценки рассчитаны!\n")
cat("     - Диапазон оценок: [", round(min(anomaly_scores), 4), ", ", 
    round(max(anomaly_scores), 4), "]\n", sep = "")
cat("     - Средняя оценка:", round(mean(anomaly_scores), 4), "\n")
cat("     - Медиана:", round(median(anomaly_scores), 4), "\n")

# Определяем порог аномалии (95-й процентиль)
threshold <- quantile(anomaly_scores, 0.95)
cat("     - Порог (95%):", round(threshold, 4), "\n")

# Добавляем оценки в данные
prepared_data$anomaly_score <- anomaly_scores
prepared_data$is_anomaly <- anomaly_scores > threshold

anomaly_count <- sum(prepared_data$is_anomaly, na.rm = TRUE)
cat("     - Найдено аномалий:", anomaly_count, 
    "из", nrow(prepared_data), 
    "(", round(100 * anomaly_count / nrow(prepared_data), 2), "%)\n\n")

# ----------------------------------------------------------------------------
# 6. ФУНКЦИЯ ОПРЕДЕЛЕНИЯ ТИПА АТАКИ
# ----------------------------------------------------------------------------

determine_attack_type <- function(row) {
  
  # DDoS-атака (много соединений, короткие, мало данных)
  ddos_score <- 0
  if (!is.na(row$conn_count_5min) && row$conn_count_5min > 500) ddos_score <- ddos_score + 2
  if (!is.na(row$dest_port_distinct) && row$dest_port_distinct < 10) ddos_score <- ddos_score + 1
  if (!is.na(row$duration) && row$duration < 0.1) ddos_score <- ddos_score + 1
  if (!is.na(row$orig_bytes) && row$orig_bytes < 100) ddos_score <- ddos_score + 1
  
  # DoS-атака (на конкретный порт/сервис)
  dos_score <- 0
  if (!is.na(row$conn_count_5min) && row$conn_count_5min > 200) dos_score <- dos_score + 1
  if (!is.na(row$dest_port_distinct) && row$dest_port_distinct == 1) dos_score <- dos_score + 2
  if (!is.na(row$missed_bytes) && row$missed_bytes > 0) dos_score <- dos_score + 1
  if (!is.na(row$duration) && row$duration > 10) dos_score <- dos_score + 1
  
  # Утечка данных (эксфильтрация)
  exfil_score <- 0
  if (!is.na(row$orig_bytes) && row$orig_bytes > 10000) exfil_score <- exfil_score + 2
  if (!is.na(row$resp_bytes) && row$resp_bytes < 500) exfil_score <- exfil_score + 1
  if (!is.na(row$duration) && row$duration > 30) exfil_score <- exfil_score + 1
  if (!is.na(row$data_volume_change) && row$data_volume_change > 500) exfil_score <- exfil_score + 1
  if (!is.na(row$uri_length) && row$uri_length > 100) exfil_score <- exfil_score + 1
  
  # Ботнет активность
  botnet_score <- 0
  if (!is.na(row$query_length) && row$query_length > 50) botnet_score <- botnet_score + 2
  if (!is.na(row$query_entropy) && row$query_entropy > 4.0) botnet_score <- botnet_score + 2
  if (!is.na(row$num_labels) && row$num_labels > 3) botnet_score <- botnet_score + 1
  if (!is.na(row$conn_count_5min) && row$conn_count_5min > 100) botnet_score <- botnet_score + 1
  if (!is.na(row$ssl_sni_entropy) && row$ssl_sni_entropy > 3.5) botnet_score <- botnet_score + 1
  
  # Сканирование портов
  scan_score <- 0
  if (!is.na(row$dest_port_distinct) && row$dest_port_distinct > 50) scan_score <- scan_score + 2
  if (!is.na(row$conn_count_5min) && row$conn_count_5min > 100) scan_score <- scan_score + 1
  if (!is.na(row$duration) && row$duration < 0.05) scan_score <- scan_score + 1
  if (!is.na(row$orig_bytes) && row$orig_bytes == 0 && (!is.na(row$resp_bytes) && row$resp_bytes == 0)) {
    scan_score <- scan_score + 1
  }
  
  # Находим максимальный score
  scores <- c(ddos = ddos_score, dos = dos_score, exfiltration = exfil_score, 
              botnet = botnet_score, port_scan = scan_score)
  max_score <- max(scores)
  
  if (max_score >= 3) {
    return(names(scores)[which.max(scores)])
  } else if (max_score >= 2) {
    return("подозрительная")
  } else {
    return("не определена")
  }
}

# ----------------------------------------------------------------------------
# 7. ФУНКЦИЯ ВЫДЕЛЕНИЯ ПРИЗНАКОВ АТАКИ
# ----------------------------------------------------------------------------

get_attack_indicators <- function(row, attack_type) {
  indicators <- c()
  
  if (attack_type == "ddos") {
    if (!is.na(row$conn_count_5min) && row$conn_count_5min > 500) indicators <- c(indicators, "высокая частота соединений")
    if (!is.na(row$dest_port_distinct) && row$dest_port_distinct < 10) indicators <- c(indicators, "ограниченный диапазон портов")
    if (!is.na(row$duration) && row$duration < 0.1) indicators <- c(indicators, "очень короткие соединения")
    if (!is.na(row$orig_bytes) && row$orig_bytes < 100) indicators <- c(indicators, "малый объём данных")
    
  } else if (attack_type == "dos") {
    if (!is.na(row$conn_count_5min) && row$conn_count_5min > 200) indicators <- c(indicators, "высокая частота")
    if (!is.na(row$dest_port_distinct) && row$dest_port_distinct == 1) indicators <- c(indicators, "один целевой порт")
    if (!is.na(row$missed_bytes) && row$missed_bytes > 0) indicators <- c(indicators, "потерянные пакеты")
    if (!is.na(row$duration) && row$duration > 10) indicators <- c(indicators, "длительные соединения")
    
  } else if (attack_type == "exfiltration") {
    if (!is.na(row$orig_bytes) && row$orig_bytes > 10000) indicators <- c(indicators, "большой объём исходящих данных")
    if (!is.na(row$resp_bytes) && row$resp_bytes < 500) indicators <- c(indicators, "мало входящих данных")
    if (!is.na(row$duration) && row$duration > 30) indicators <- c(indicators, "длительное соединение")
    if (!is.na(row$data_volume_change) && row$data_volume_change > 500) indicators <- c(indicators, "резкий скачок трафика")
    if (!is.na(row$uri_length) && row$uri_length > 100) indicators <- c(indicators, "длинные URI")
    
  } else if (attack_type == "botnet") {
    if (!is.na(row$query_length) && row$query_length > 50) indicators <- c(indicators, "длинные DNS-запросы (DGA)")
    if (!is.na(row$query_entropy) && row$query_entropy > 4.0) indicators <- c(indicators, "высокая энтропия DNS-имён")
    if (!is.na(row$num_labels) && row$num_labels > 3) indicators <- c(indicators, "много уровней в домене")
    if (!is.na(row$conn_count_5min) && row$conn_count_5min > 100) indicators <- c(indicators, "высокая активность")
    if (!is.na(row$ssl_sni_entropy) && row$ssl_sni_entropy > 3.5) indicators <- c(indicators, "подозрительный SNI")
    
  } else if (attack_type == "port_scan") {
    if (!is.na(row$dest_port_distinct) && row$dest_port_distinct > 50) indicators <- c(indicators, "много уникальных портов")
    if (!is.na(row$conn_count_5min) && row$conn_count_5min > 100) indicators <- c(indicators, "высокая частота")
    if (!is.na(row$duration) && row$duration < 0.05) indicators <- c(indicators, "очень короткие соединения")
    if (!is.na(row$orig_bytes) && row$orig_bytes == 0 && (!is.na(row$resp_bytes) && row$resp_bytes == 0)) {
      indicators <- c(indicators, "нет передачи данных")
    }
  }
  
  if (length(indicators) == 0) return("стандартные метрики аномальности")
  return(paste(indicators, collapse = ", "))
}

# ----------------------------------------------------------------------------
# 8. ФУНКЦИЯ ИЗВЛЕЧЕНИЯ PAYLOAD
# ----------------------------------------------------------------------------

get_payload_info <- function(row) {
  payload_parts <- c()
  
  # HTTP payload
  if (has_column(row, "http_method") && !is.na(row$http_method) && row$http_method != "NA" && row$http_method != "") {
    payload_parts <- c(payload_parts, paste0("HTTP_метод=", row$http_method))
  }
  if (!is.na(row$uri_length) && row$uri_length > 0) {
    payload_parts <- c(payload_parts, paste0("URI_длина=", row$uri_length))
  }
  if (!is.na(row$ua_length) && row$ua_length > 0) {
    payload_parts <- c(payload_parts, paste0("User-Agent_длина=", row$ua_length))
  }
  
  # DNS payload
  if (!is.na(row$query_length) && row$query_length > 0) {
    payload_parts <- c(payload_parts, paste0("DNS_запрос_длина=", row$query_length))
    if (!is.na(row$query_entropy)) {
      payload_parts <- c(payload_parts, paste0("DNS_энтропия=", round(row$query_entropy, 2)))
    }
    if (!is.na(row$num_labels) && row$num_labels > 0) {
      payload_parts <- c(payload_parts, paste0("DNS_уровней=", row$num_labels))
    }
  }
  
  # SSL payload
  if (!is.na(row$ssl_sni_length) && row$ssl_sni_length > 0) {
    payload_parts <- c(payload_parts, paste0("SSL_SNI_длина=", row$ssl_sni_length))
  }
  
  # Размеры трафика
  if (!is.na(row$orig_bytes) && row$orig_bytes > 0) {
    payload_parts <- c(payload_parts, paste0("исходящий_трафик=", row$orig_bytes, " байт"))
  }
  if (!is.na(row$resp_bytes) && row$resp_bytes > 0) {
    payload_parts <- c(payload_parts, paste0("входящий_трафик=", row$resp_bytes, " байт"))
  }
  
  if (length(payload_parts) == 0) return("нет данных (REJ/S0 соединение)")
  return(paste(payload_parts, collapse = ", "))
}

# ----------------------------------------------------------------------------
# 9. ОСНОВНАЯ ФУНКЦИЯ ОБНАРУЖЕНИЯ АТАК
# ----------------------------------------------------------------------------

detect_attacks <- function(data) {
  
  anomalies <- data[data$is_anomaly == TRUE, ]
  
  if (nrow(anomalies) == 0) {
    cat("\n Аномалий не обнаружено. Сеть работает штатно.\n")
    return(NULL)
  }
  
  cat("\n", paste(rep("=", 80), collapse = ""), "\n", sep = "")
  cat(" ОБНАРУЖЕНЫ АНОМАЛИИ В СЕТИ \n")
  cat(paste(rep("=", 80), collapse = ""), "\n\n", sep = "")
  
  results <- list()
  
  for (i in 1:nrow(anomalies)) {
    row <- anomalies[i, ]
    
    # Определяем тип атаки
    attack_type <- determine_attack_type(row)
    
    # Формируем результат
    result <- list(
      session_id = ifelse("uid" %in% colnames(row), row$uid, paste0("session_", i)),
      timestamp = ifelse("ts" %in% colnames(row), row$ts, NA),
      src_ip = ifelse("src_ip" %in% colnames(row), row$src_ip, "unknown"),
      src_port = ifelse("src_port" %in% colnames(row), row$src_port, NA),
      dst_ip = ifelse("dst_ip" %in% colnames(row), row$dst_ip, "unknown"),
      dst_port = ifelse("dst_port" %in% colnames(row), row$dst_port, NA),
      duration = ifelse("duration" %in% colnames(row), row$duration, NA),
      proto = ifelse("proto" %in% colnames(row), as.character(row$proto), "unknown"),
      anomaly_score = row$anomaly_score,
      attack_type = attack_type,
      payload = get_payload_info(row),
      indicators = get_attack_indicators(row, attack_type)
    )
    
    results[[i]] <- result
    
    # ВЫВОД РЕЗУЛЬТАТА
    cat(paste(rep("-", 80), collapse = ""), "\n")
    cat(" АТАКА #", i, " | Оценка аномальности: ", round(row$anomaly_score, 4), "\n", sep = "")
    cat("ТИП АТАКИ: ", toupper(attack_type), "\n", sep = "")
    cat(paste(rep("-", 80), collapse = ""), "\n")
    
    cat(" SESSION ID (UID):", result$session_id, "\n")
    if (!is.na(result$timestamp)) cat("📅 ВРЕМЯ:", result$timestamp, "\n")
    cat("\n")
    
    cat(" ИСТОЧНИК (Source):\n")
    cat("   IP-адрес:", result$src_ip, "\n")
    cat("   Порт:", result$src_port, "\n")
    cat("\n")
    
    cat(" НАЗНАЧЕНИЕ (Destination):\n")
    cat("   IP-адрес:", result$dst_ip, "\n")
    cat("   Порт:", result$dst_port, "\n")
    cat("\n")
    
    cat(" ПАРАМЕТРЫ СОЕДИНЕНИЯ:\n")
    if (!is.na(result$duration)) cat("   Длительность:", result$duration, "сек\n")
    cat("   Протокол:", result$proto, "\n")
    if ("conn_state" %in% colnames(row)) cat("   Состояние:", row$conn_state, "\n")
    if ("history" %in% colnames(row)) cat("   История флагов:", row$history, "\n")
    cat("\n")
    
    cat(" PAYLOAD ТРАФИКА:\n")
    cat("   ", result$payload, "\n")
    cat("\n")
    
    cat(" ПРИЗНАКИ ВЫЯВЛЕНИЯ АТАКИ:\n")
    cat("   ", result$indicators, "\n")
    cat("\n")
    
    cat(" ДОПОЛНИТЕЛЬНЫЕ МЕТРИКИ:\n")
    if ("orig_bytes" %in% colnames(row)) cat("   Исходящие байты:", row$orig_bytes, "\n")
    if ("resp_bytes" %in% colnames(row)) cat("   Входящие байты:", row$resp_bytes, "\n")
    if ("missed_bytes" %in% colnames(row)) cat("   Пропущенные байты:", row$missed_bytes, "\n")
    if ("conn_count_5min" %in% colnames(row)) cat("   Соединений за 5 мин:", row$conn_count_5min, "\n")
    if ("dest_port_distinct" %in% colnames(row)) cat("   Уникальных портов:", row$dest_port_distinct, "\n")
    if ("unique_dst_ip" %in% colnames(row)) cat("   Уникальных IP назначения:", row$unique_dst_ip, "\n")
    if ("data_volume_change" %in% colnames(row)) cat("   Изменение объёма данных:", round(row$data_volume_change, 2), "%\n")
    cat("\n")
    
    # Рекомендации
    if (attack_type %in% c("ddos", "dos")) {
      cat("⚠️ РЕКОМЕНДАЦИЯ: Блокировать источник", result$src_ip, "\n")
    } else if (attack_type == "exfiltration") {
      cat("⚠️ РЕКОМЕНДАЦИЯ: Проверить", result$dst_ip, "на наличие утечек данных\n")
    } else if (attack_type == "botnet") {
      cat("⚠️ РЕКОМЕНДАЦИЯ: Проверить", result$src_ip, "на наличие вредоносного ПО\n")
    } else if (attack_type == "port_scan") {
      cat("⚠️ РЕКОМЕНДАЦИЯ: Активировать защиту от сканирования, заблокировать", result$src_ip, "\n")
    }
    cat("\n")
  }
  
  cat(paste(rep("=", 80), collapse = ""), "\n")
  cat("📊 ИТОГО ОБНАРУЖЕНО АТАК:", length(results), "\n")
  cat(paste(rep("=", 80), collapse = ""), "\n\n")
  
  return(results)
}

# ----------------------------------------------------------------------------
# 10. ЗАПУСК ОБНАРУЖЕНИЯ АТАК
# ----------------------------------------------------------------------------

cat("=== 5. ЗАПУСК ОБНАРУЖЕНИЯ АТАК ===\n\n")

detection_results <- detect_attacks(prepared_data)

# ----------------------------------------------------------------------------
# 11. СОХРАНЕНИЕ РЕЗУЛЬТАТОВ
# ----------------------------------------------------------------------------

if (!is.null(detection_results) && length(detection_results) > 0) {
  
  # Сохраняем результаты в CSV
  results_df <- do.call(rbind, lapply(detection_results, function(x) {
    data.frame(
      session_id = x$session_id,
      timestamp = ifelse(is.null(x$timestamp), NA, x$timestamp),
      src_ip = x$src_ip,
      src_port = x$src_port,
      dst_ip = x$dst_ip,
      dst_port = x$dst_port,
      duration = x$duration,
      proto = x$proto,
      anomaly_score = x$anomaly_score,
      attack_type = x$attack_type,
      indicators = x$indicators,
      stringsAsFactors = FALSE
    )
  }))
  
  write.csv(results_df, "detected_attacks.csv", row.names = FALSE)
  cat("\n✅ Результаты сохранены в 'detected_attacks.csv'\n")
  
  # Статистика по типам атак
  cat("\n=== СТАТИСТИКА ПО ТИПАМ АТАК ===\n")
  attack_stats <- table(results_df$attack_type)
  for (attack_type in names(attack_stats)) {
    cat("  ", toupper(attack_type), ":", attack_stats[attack_type], "\n")
  }
  
  # --------------------------------------------------------------------------
  # 12. ВИЗУАЛИЗАЦИЯ
  # --------------------------------------------------------------------------
  
  # График распределения оценок
  p <- ggplot(prepared_data, aes(x = anomaly_score)) +
    geom_histogram(bins = 50, fill = "steelblue", color = "white", alpha = 0.7) +
    geom_vline(xintercept = threshold, color = "red", linetype = "dashed", size = 1) +
    labs(
      title = "Распределение оценок аномальности",
      subtitle = paste("Порог (95%):", round(threshold, 4), "| Аномалий:", sum(prepared_data$is_anomaly)),
      x = "Оценка аномальности (0-1)",
      y = "Количество сессий"
    ) +
    theme_minimal() +
    theme(plot.title = element_text(hjust = 0.5, face = "bold"))
  
  ggsave("anomaly_scores_distribution.png", plot = p, width = 10, height = 6)
  cat(" График сохранён в 'anomaly_scores_distribution.png'\n")
}

# ----------------------------------------------------------------------------
# 13. ИТОГИ
# ----------------------------------------------------------------------------

cat("\n", paste(rep("=", 80), collapse = ""), "\n", sep = "")
cat(" АНАЛИЗ ЗАВЕРШЁН\n")
cat(paste(rep("=", 80), collapse = ""), "\n", sep = "")

# Вывод summary
cat("\n ИТОГОВАЯ СТАТИСТИКА:\n")
cat("   - Всего обработано сессий:", nrow(prepared_data), "\n")
cat("   - Обнаружено аномалий:", sum(prepared_data$is_anomaly), "\n")
if (!is.null(detection_results)) {
  cat("   - Классифицировано атак:", length(detection_results), "\n")
}
cat("   - Использовано признаков:", ncol(model_features), "\n")
cat("\n")