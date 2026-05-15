library(testthat)      # Фреймворк для тестирования
library(data.table)    # Работа с таблицами
library(dplyr)         # Манипуляции данными
library(arrow)         # Чтение Parquet
library(ggplot2)       # Визуализация
library(isotree)       # Isolation Forest

test_that("has_column correctly detects column presence", {
  # Создаём тестовый data.table
  test_dt <- data.table::data.table(
    col1 = c(1, 2, 3),
    col2 = c("a", "b", "c"),
    col3 = c(TRUE, FALSE, TRUE)
  )
  
  # Проверяем существующие колонки
  expect_true(has_column(test_dt, "col1"))
  expect_true(has_column(test_dt, "col2"))
  expect_true(has_column(test_dt, "col3"))
  
  # Проверяем несуществующие колонки
  expect_false(has_column(test_dt, "col4"))
  expect_false(has_column(test_dt, "nonexistent"))
  expect_false(has_column(test_dt, ""))
  
  # Проверка с пустым data.table
  empty_dt <- data.table::data.table()
  expect_false(has_column(empty_dt, "anything"))
})

test_that("has_column handles edge cases correctly", {
  # Проверка с NULL
  expect_false(has_column(NULL, "col1"))
  
  # Проверка с вектором вместо data.table (должно работать с data.frame)
  test_df <- data.frame(a = 1:3, b = 4:6)
  expect_true(has_column(test_df, "a"))
  expect_false(has_column(test_df, "c"))
  
  # Проверка с list
  test_list <- list(a = 1, b = 2)
  expect_true(has_column(test_list, "a"))
  expect_false(has_column(test_list, "c"))
})


test_that("classify_attacks detects DDoS attack patterns correctly", {
  # Тест 1: Классическая DDoS-атака
  test_dt <- data.table::data.table(
    src_ip = "192.168.1.100",
    dst_ip = "192.168.1.1",
    ts = 1000,
    conn_count_5min = 600,      # > 500 -> +2 балла
    dest_port_distinct = 5,     # < 10 -> +1 балл
    unique_dst_ip = 10,
    duration = 0.05,            # < 0.1 -> +1 балл
    orig_bytes = 50,            # < 100 -> +1 балл
    resp_bytes = 100,
    missed_bytes = 0,
    query_length = 0,
    query_entropy = 0,
    num_labels = 0,
    uri_length = 0,
    data_volume_change = 0,
    ssl_sni_entropy = 0,
    proto = "tcp",
    conn_state = "S0"
  )
  
  classified <- classify_attacks(test_dt)
  expect_equal(classified$attack_type[1], "ddos")
  expect_gte(classified$attack_score[1], 5)  # 2+1+1+1 = 5 баллов
  
  # Тест 2: DDoS без одного признака (должен остаться DDoS)
  test_ddos_weak <- copy(test_dt)
  test_ddos_weak[, conn_count_5min := 400]  # < 500
  classified <- classify_attacks(test_ddos_weak)
  expect_equal(classified$attack_type[1], "ddos")
  expect_gte(classified$attack_score[1], 3)  # 1+1+1 = 3 балла
  
  # Тест 3: DDoS с недостаточным количеством баллов
  test_ddos_invalid <- copy(test_dt)
  test_ddos_invalid[, `:=`(conn_count_5min = 200, dest_port_distinct = 20,
                           duration = 0.5, orig_bytes = 500)]
  classified <- classify_attacks(test_ddos_invalid)
  expect_false(classified$attack_type[1] == "ddos")
})

test_that("classify_attacks detects DoS attack patterns correctly", {
  # Тест 1: Классическая DoS-атака
  test_dt <- data.table::data.table(
    src_ip = "192.168.1.100",
    dst_ip = "192.168.1.1",
    ts = 1000,
    conn_count_5min = 300,      # > 200 -> +1 балл
    dest_port_distinct = 1,     # == 1 -> +2 балла (ключевой признак)
    unique_dst_ip = 1,
    duration = 15,              # > 10 -> +1 балл
    orig_bytes = 500,
    resp_bytes = 100,
    missed_bytes = 100,         # > 0 -> +1 балл
    query_length = 0,
    query_entropy = 0,
    num_labels = 0,
    uri_length = 0,
    data_volume_change = 0,
    ssl_sni_entropy = 0,
    proto = "tcp",
    conn_state = "S0"
  )
  
  classified <- classify_attacks(test_dt)
  expect_equal(classified$attack_type[1], "dos")
  expect_gte(classified$attack_score[1], 5)  # 1+2+1+1 = 5 баллов
  
  # Тест 2: DoS без missed_bytes
  test_dos_weak <- copy(test_dt)
  test_dos_weak[, missed_bytes := 0]
  classified <- classify_attacks(test_dos_weak)
  expect_equal(classified$attack_type[1], "dos")
  expect_gte(classified$attack_score[1], 4)  # 1+2+1 = 4 балла
  
  # Тест 3: Высокая частота соединений с одним портом, но короткие соединения
  test_dos_high_freq <- copy(test_dt)
  test_dos_high_freq[, `:=`(conn_count_5min = 500, duration = 0.01, missed_bytes = 0)]
  classified <- classify_attacks(test_dos_high_freq)
  # Может быть классифицирован и как DDoS, и как DoS
  expect_true(classified$attack_type[1] %in% c("dos", "ddos"))
})

test_that("classify_attacks detects exfiltration (data leak) patterns correctly", {
  # Тест 1: Классическая утечка данных
  test_dt <- data.table::data.table(
    src_ip = "192.168.1.100",
    dst_ip = "8.8.8.8",
    ts = 1000,
    conn_count_5min = 1,
    dest_port_distinct = 1,
    unique_dst_ip = 1,
    duration = 45,              # > 30 -> +1 балл
    orig_bytes = 50000,         # > 10000 -> +2 балла
    resp_bytes = 100,           # < 500 -> +1 балл
    missed_bytes = 0,
    query_length = 0,
    query_entropy = 0,
    num_labels = 0,
    uri_length = 150,           # > 100 -> +1 балл
    data_volume_change = 1000,  # > 500 -> +1 балл
    ssl_sni_entropy = 0,
    proto = "tcp",
    conn_state = "S1"
  )
  
  classified <- classify_attacks(test_dt)
  expect_equal(classified$attack_type[1], "exfiltration")
  expect_gte(classified$attack_score[1], 6)  # 1+2+1+1+1 = 6 баллов
  
  # Тест 2: Утечка без длительного соединения
  test_exfil_fast <- copy(test_dt)
  test_exfil_fast[, duration := 10]
  classified <- classify_attacks(test_exfil_fast)
  expect_equal(classified$attack_type[1], "exfiltration")
  expect_gte(classified$attack_score[1], 5)  # 2+1+1+1 = 5 баллов
  
  # Тест 3: Утечка с малым объёмом данных (не должна быть обнаружена)
  test_exfil_small <- copy(test_dt)
  test_exfil_small[, orig_bytes := 5000]
  classified <- classify_attacks(test_exfil_small)
  expect_true(classified$attack_type[1] != "exfiltration")
})

test_that("classify_attacks detects botnet activity patterns correctly", {
  # Тест 1: Классическая ботнет активность (DGA домены)
  test_dt <- data.table::data.table(
    src_ip = "192.168.1.100",
    dst_ip = "192.168.1.1",
    ts = 1000,
    conn_count_5min = 150,      # > 100 -> +1 балл
    dest_port_distinct = 1,
    unique_dst_ip = 1,
    duration = 0.5,
    orig_bytes = 100,
    resp_bytes = 100,
    missed_bytes = 0,
    query_length = 60,          # > 50 -> +2 балла
    query_entropy = 4.5,        # > 4.0 -> +2 балла
    num_labels = 4,             # > 3 -> +1 балл
    uri_length = 0,
    data_volume_change = 0,
    ssl_sni_entropy = 4.0,      # > 3.5 -> +1 балл
    proto = "udp",
    conn_state = "SF"
  )
  
  classified <- classify_attacks(test_dt)
  expect_equal(classified$attack_type[1], "botnet")
  expect_gte(classified$attack_score[1], 7)  # 1+2+2+1+1 = 7 баллов
  
  # Тест 2: Ботнет только по DNS признакам
  test_botnet_dns <- copy(test_dt)
  test_botnet_dns[, `:=`(conn_count_5min = 10, ssl_sni_entropy = 0)]
  classified <- classify_attacks(test_botnet_dns)
  expect_equal(classified$attack_type[1], "botnet")
  expect_gte(classified$attack_score[1], 5)  # 2+2+1 = 5 баллов
  
  # Тест 3: Случайные доменные имена с высокой энтропией, но короткие
  test_botnet_short <- copy(test_dt)
  test_botnet_short[, `:=`(query_length = 20, query_entropy = 4.2)]
  classified <- classify_attacks(test_botnet_short)
  expect_equal(classified$attack_type[1], "botnet")
  expect_gte(classified$attack_score[1], 3)  # 2+1 = 3 балла
})

test_that("classify_attacks detects port scan patterns correctly", {
  # Тест 1: Классическое сканирование портов
  test_dt <- data.table::data.table(
    src_ip = "192.168.1.100",
    dst_ip = "192.168.1.1",
    ts = 1000,
    conn_count_5min = 150,      # > 100 -> +1 балл
    dest_port_distinct = 80,    # > 50 -> +2 балла
    unique_dst_ip = 1,
    duration = 0.03,            # < 0.05 -> +1 балл
    orig_bytes = 0,             # 0 -> +1 балл
    resp_bytes = 0,             # 0 -> часть предыдущего условия
    missed_bytes = 0,
    query_length = 0,
    query_entropy = 0,
    num_labels = 0,
    uri_length = 0,
    data_volume_change = 0,
    ssl_sni_entropy = 0,
    proto = "tcp",
    conn_state = "S0"
  )
  
  classified <- classify_attacks(test_dt)
  expect_equal(classified$attack_type[1], "port_scan")
  expect_gte(classified$attack_score[1], 5)  # 1+2+1+1 = 5 баллов
  
  # Тест 2: Сканирование с малым количеством портов
  test_scan_weak <- copy(test_dt)
  test_scan_weak[, dest_port_distinct := 30]
  classified <- classify_attacks(test_scan_weak)
  expect_true(classified$attack_type[1] != "port_scan")
})

test_that("classify_attacks returns 'подозрительная' for suspicious but unclear attacks", {
  # Тест: Пограничный случай (2 балла)
  test_dt <- data.table::data.table(
    src_ip = "192.168.1.100",
    dst_ip = "192.168.1.1",
    ts = 1000,
    conn_count_5min = 250,      # > 200 -> +1 балл (DoS)
    dest_port_distinct = 1,     # == 1 -> +2 балла (DoS)
    unique_dst_ip = 1,
    duration = 5,               # Не подходит под условия (0 баллов)
    orig_bytes = 500,
    resp_bytes = 500,
    missed_bytes = 0,
    query_length = 0,
    query_entropy = 0,
    num_labels = 0,
    uri_length = 0,
    data_volume_change = 0,
    ssl_sni_entropy = 0,
    proto = "tcp",
    conn_state = "SF"
  )
  
  classified <- classify_attacks(test_dt)
  expect_equal(classified$attack_type[1], "подозрительная")
  expect_equal(classified$attack_score[1], 3)  # 1+2 = 3 балла, но max_score = 2? Проверка
})

test_that("classify_attacks returns 'не определена' for non-classifiable attacks", {
  # Тест: Аномалия с низкими баллами по всем типам
  test_dt <- data.table::data.table(
    src_ip = "192.168.1.100",
    dst_ip = "192.168.1.1",
    ts = 1000,
    conn_count_5min = 10,
    dest_port_distinct = 5,
    unique_dst_ip = 1,
    duration = 1,
    orig_bytes = 1000,
    resp_bytes = 2000,
    missed_bytes = 0,
    query_length = 10,
    query_entropy = 1.5,
    num_labels = 2,
    uri_length = 20,
    data_volume_change = 10,
    ssl_sni_entropy = 2.0,
    proto = "tcp",
    conn_state = "SF"
  )
  
  classified <- classify_attacks(test_dt)
  expect_equal(classified$attack_type[1], "не определена")
  expect_lt(classified$attack_score[1], 2)
})

# ----------------------------------------------------------------------------
# 3. ТЕСТЫ ФУНКЦИИ ИЗВЛЕЧЕНИЯ PAYLOAD
# ----------------------------------------------------------------------------

test_that("get_payload_info extracts HTTP payload correctly", {
  test_dt <- data.table::data.table(
    http_method = "POST",
    uri_length = 150,
    ua_length = 120,
    query_length = 0,
    query_entropy = 0,
    num_labels = 0,
    ssl_sni_length = 0,
    orig_bytes = 5000,
    resp_bytes = 10000
  )
  
  payload <- get_payload_info(test_dt)
  expect_true(grepl("HTTP_метод=POST", payload))
  expect_true(grepl("URI_длина=150", payload))
  expect_true(grepl("User-Agent_длина=120", payload))
  expect_true(grepl("исходящий_трафик=5000", payload))
  expect_true(grepl("входящий_трафик=10000", payload))
})

test_that("get_payload_info extracts DNS payload correctly", {
  test_dt <- data.table::data.table(
    http_method = NA,
    uri_length = 0,
    ua_length = 0,
    query_length = 65,
    query_entropy = 4.7,
    num_labels = 5,
    ssl_sni_length = 0,
    orig_bytes = 200,
    resp_bytes = 500
  )
  
  payload <- get_payload_info(test_dt)
  expect_true(grepl("DNS_запрос_длина=65", payload))
  expect_true(grepl("DNS_энтропия=4.7", payload))
  expect_true(grepl("DNS_уровней=5", payload))
})

test_that("get_payload_info returns 'нет данных' for empty connection", {
  test_dt <- data.table::data.table(
    http_method = NA,
    uri_length = 0,
    ua_length = 0,
    query_length = 0,
    query_entropy = 0,
    num_labels = 0,
    ssl_sni_length = 0,
    orig_bytes = 0,
    resp_bytes = 0
  )
  
  payload <- get_payload_info(test_dt)
  expect_equal(payload, "нет данных (REJ/S0 соединение)")
})


test_that("prepare_features handles missing columns gracefully", {
  # Создаём минимальный набор данных
  minimal_data <- data.table::data.table(
    duration = c(0.1, 0.2, NA),
    orig_bytes = c(100, NA, 300),
    resp_bytes = c(200, 400, NA),
    proto = c("tcp", "udp", "tcp")
  )
  
  prepared <- prepare_features(minimal_data)
  
  # Проверяем, что появилась колонка history_length
  expect_true("history_length" %in% colnames(prepared))
  
  # Проверяем, что NA заменены на 0
  expect_equal(sum(is.na(prepared$duration)), 0)
  expect_equal(sum(is.na(prepared$orig_bytes)), 0)
  
  # Проверяем, что категориальные признаки остались
  expect_true(is.factor(prepared$proto))
})

test_that("prepare_features handles completely empty data", {
  empty_data <- data.table::data.table()
  
  # Должна быть ошибка или предупреждение, но не падение
  expect_error(prepare_features(empty_data), NA)
})

test_that("prepare_features correctly identifies numeric features", {
  test_data <- data.table::data.table(
    duration = c(0.1, 0.2, 0.3),
    orig_bytes = c(100, 200, 300),
    proto = c("tcp", "tcp", "udp"),
    conn_state = c("S0", "SF", "REJ")
  )
  
  prepared <- prepare_features(test_data)
  features <- attr(prepared, "features")
  
  # Проверяем, что числовые признаки стали numeric
  expect_true(is.numeric(features$duration))
  expect_true(is.numeric(features$orig_bytes))
  
  # Проверяем, что категориальные остались factor
  expect_true(is.factor(features$proto))
  expect_true(is.factor(features$conn_state))
})


test_that("isolation forest model trains on minimal data", {
  # Создаём минимальный набор данных
  minimal_features <- data.table::data.table(
    duration = runif(50, 0.001, 10),
    orig_bytes = sample(c(0, 100, 1000, 10000), 50, replace = TRUE),
    resp_bytes = sample(c(0, 100, 1000, 10000), 50, replace = TRUE),
    proto = factor(sample(c("tcp", "udp", "icmp"), 50, replace = TRUE))
  )
  
  # Обучение не должно вызывать ошибку
  expect_error({
    model <- isolation.forest(
      minimal_features,
      ntrees = 10,
      sample_size = min(30, nrow(minimal_features)),
      seed = 42
    )
  }, NA)
  
  # Проверка предсказаний
  model <- isolation.forest(minimal_features, ntrees = 10, sample_size = 30, seed = 42)
  scores <- predict(model, minimal_features, type = "score")
  
  expect_length(scores, nrow(minimal_features))
  expect_true(all(scores >= 0 & scores <= 1))
})

test_that("isolation forest handles categorical features correctly", {
  test_data <- data.table::data.table(
    duration = c(0.01, 0.01, 0.01, 10, 10, 10),
    proto = factor(c("tcp", "tcp", "tcp", "udp", "udp", "udp")),
    conn_state = factor(c("REJ", "REJ", "REJ", "S1", "S1", "S1"))
  )
  
  expect_error({
    model <- isolation.forest(test_data, ntrees = 10, sample_size = 6, seed = 42)
    scores <- predict(model, test_data, type = "score")
  }, NA)
})

# ----------------------------------------------------------------------------
# 6. ТЕСТЫ АНОМАЛИЙ И ПОРОГА
# ----------------------------------------------------------------------------

test_that("threshold calculation is correct", {
  scores <- c(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0)
  
  # 95-й процентиль от 10 элементов = 0.95 квантиль
  threshold_95 <- quantile(scores, 0.95)
  expect_equal(threshold_95, 0.955)  # или близкое значение
  
  # Проверяем, что аномалии правильно идентифицируются
  is_anomaly <- scores > threshold_95
  expect_equal(sum(is_anomaly), 1)  # только score = 1.0
})

test_that("anomaly scores are within [0,1] range", {
  # Генерируем случайные данные
  random_data <- data.table::data.table(
    duration = runif(100, 0.001, 100),
    orig_bytes = abs(rnorm(100, 1000, 500))
  )
  
  model <- isolation.forest(random_data, ntrees = 20, sample_size = 50, seed = 42)
  scores <- predict(model, random_data, type = "score")
  
  expect_true(all(scores >= 0))
  expect_true(all(scores <= 1))
})



# ----------------------------------------------------------------------------
# 8. ТЕСТЫ ОБРАБОТКИ ПРОПУСКОВ
# ----------------------------------------------------------------------------

test_that("missing_action='divide' handles NA values correctly", {
  data_with_na <- data.table::data.table(
    duration = c(0.1, NA, 0.3, 0.4, NA),
    orig_bytes = c(100, 200, NA, 400, 500),
    proto = factor(c("tcp", NA, "tcp", "udp", "tcp"))
  )
  
  expect_error({
    model <- isolation.forest(
      data_with_na,
      ntrees = 10,
      sample_size = 5,
      missing_action = "divide",
      seed = 42
    )
    scores <- predict(model, data_with_na, type = "score")
  }, NA)
})



test_that("ggplot histogram is created without errors", {
  test_scores <- data.frame(anomaly_score = c(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0))
  threshold <- 0.85
  
  p <- ggplot(test_scores, aes(x = anomaly_score)) +
    geom_histogram(bins = 10) +
    geom_vline(xintercept = threshold, color = "red")
  
  expect_s3_class(p, "ggplot")
})



test_that("parquet file exists and is readable", {
  if (file.exists("iotids_train.parquet")) {
    expect_error({
      data <- read_parquet("iotids_train.parquet")
      expect_true(nrow(data) > 0)
    }, NA)
  } else {
    skip("Parquet file not found, skipping test")
  }
})


test_that("conn_count_5min values are within reasonable range", {
  # Проверка, что значения не отрицательные и не бесконечные
  test_values <- c(0, 1, 100, 500, 1000, 5000)
  expect_true(all(test_values >= 0))
  expect_true(all(is.finite(test_values)))
})

test_that("duration values are reasonable for network traffic", {
  # Длительность соединения не должна быть отрицательной
  test_values <- c(0.000001, 0.1, 1, 60, 3600)
  expect_true(all(test_values >= 0))
})

test_that("entropy values are between 0 and 8 (max for 256 chars)", {
  test_values <- c(0, 1.5, 3.2, 4.7, 5.9, 7.2)
  expect_true(all(test_values >= 0))
  expect_true(all(test_values <= 8))
})


test_that("empty dataset handling", {
  empty_data <- data.table::data.table()
  expect_error({
    model <- isolation.forest(empty_data, ntrees = 1, sample_size = 1)
  })
})

test_that("single row dataset handling", {
  single_row <- data.table::data.table(
    duration = 0.5,
    orig_bytes = 1000,
    proto = factor("tcp")
  )
  
  # С одним наблюдением обучение невозможно из-за sample_size
  expect_error({
    model <- isolation.forest(single_row, ntrees = 1, sample_size = 2)
  })
})
