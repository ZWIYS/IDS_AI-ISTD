with_temp_ids_config <- function(expr) {
  ns <- asNamespace("idsAiIstd")
  old_root <- get("PROJECT_ROOT", envir = ns)
  tmp_root <- tempfile("ids-root-")
  dir.create(tmp_root, recursive = TRUE)
  idsAiIstd::init_ids_config(tmp_root)
  on.exit(idsAiIstd::init_ids_config(old_root), add = TRUE)
  eval.parent(substitute(expr))
}

testthat::test_that(".adaptive_min handles floor, adaptive scaling, and hard base cap", {
  testthat::expect_equal(
    idsAiIstd:::.adaptive_min(c(NA_real_, -1), base = 500, frac = 0.75, floor_val = 2L),
    2
  )
  testthat::expect_equal(
    idsAiIstd:::.adaptive_min(c(100, 200), base = 500, frac = 0.5, floor_val = 2L),
    100
  )
  testthat::expect_equal(
    idsAiIstd:::.adaptive_min(c(10000), base = 500, frac = 0.9, floor_val = 2L),
    500
  )
})

testthat::test_that(".load_model_meta returns NULL for absent file and reads existing metadata", {
  p <- tempfile(fileext = ".rds")
  testthat::expect_null(idsAiIstd:::.load_model_meta(p))

  saveRDS(list(threshold = 0.88, note = "meta"), p)
  m <- idsAiIstd:::.load_model_meta(p)

  testthat::expect_equal(m$threshold, 0.88)
  testthat::expect_equal(m$note, "meta")
})

testthat::test_that(".ensure_rule_cols injects all rule columns with defaults", {
  dt <- data.table::data.table(src_ip = "10.0.0.1", ts = 1)
  out <- idsAiIstd:::.ensure_rule_cols(data.table::copy(dt))

  need <- c(
    "conn_count_5min", "dest_port_distinct", "unique_dst_ip",
    "duration", "orig_bytes", "resp_bytes",
    "query_entropy", "query_length", "uri_length", "http_status_code",
    "ssl_sni_entropy", "ssl_sni_length", "data_volume_change"
  )

  testthat::expect_true(all(need %in% names(out)))
  testthat::expect_equal(out$conn_count_5min, 0)
  testthat::expect_equal(out$dest_port_distinct, 0)
  testthat::expect_equal(out$ssl_sni_length, 0)
})

testthat::test_that("classify_attacks identifies diverse attack scenarios in one batch", {
  dt <- data.table::data.table(
    scenario = c(
      "ddos", "port_scan", "exfiltration", "botnet", "dos",
      "dns_anomaly", "http_anomaly", "ssl_anomaly",
      "traffic_spike", "proxy_tunnel", "fallback"
    ),
    conn_count_5min = c(600, 150, 350, 250, 450, 1, 1, 1, 1, 1, 1),
    dest_port_distinct = c(2, 70, 10, 10, 10, 1, 1, 1, 1, 1, 1),
    unique_dst_ip = c(1, 1, 1, 30, 1, 1, 1, 1, 1, 1, 1),
    duration = c(1, 1, 5, 2, 0.05, 1, 1, 1, 1, 1, 1),
    orig_bytes = c(100, 20, 200000, 500, 100, 1, 1, 1, 1, 1, 1),
    resp_bytes = c(10, 5, 100, 200, 100, 1, 1, 1, 1, 1, 1),
    query_entropy = c(0, 0, 0, 0, 0, 4.5, 0, 0, 0, 0, 0),
    query_length = c(0, 0, 0, 0, 0, 50, 0, 0, 0, 0, 0),
    uri_length = c(0, 0, 0, 0, 0, 0, 200, 0, 0, 0, 0),
    http_status_code = c(0, 0, 0, 0, 0, 0, 500, 0, 0, 0, 0),
    ssl_sni_entropy = c(0, 0, 0, 0, 0, 0, 0, 4.0, 0, 0, 0),
    ssl_sni_length = c(0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0),
    data_volume_change = c(0, 0, 0, 0, 0, 0, 0, 0, 180, 0, 0),
    service = c("", "", "", "", "", "", "", "", "", "socks", "")
  )

  out <- idsAiIstd::classify_attacks(dt)

  testthat::expect_equal(
    out$attack_type,
    c(
      "ddos", "port_scan", "exfiltration", "botnet", "dos",
      "dns_anomaly", "http_anomaly", "ssl_anomaly",
      "traffic_spike", "proxy_tunnel", "ml_anomaly"
    )
  )
  testthat::expect_true(all(out$attack_score >= 1L))
})

testthat::test_that("classify_attacks uses custom fallback_type when no rules match", {
  rules <- idsAiIstd:::DETECT_PARAMS$rules
  rules$fallback_type <- "suspicious_custom"

  dt <- data.table::data.table(
    conn_count_5min = 1,
    dest_port_distinct = 1,
    unique_dst_ip = 1,
    duration = 1,
    orig_bytes = 1,
    resp_bytes = 1,
    query_entropy = 0,
    query_length = 0,
    uri_length = 0,
    http_status_code = 200,
    ssl_sni_entropy = 0,
    ssl_sni_length = 0,
    data_volume_change = 0,
    service = ""
  )

  out <- idsAiIstd::classify_attacks(dt, rules = rules)
  testthat::expect_equal(out$attack_type, "suspicious_custom")
})

testthat::test_that(".refine_alerts applies margin, min score, quantile and dedup", {
  alerts <- data.table::data.table(
    src_ip = c("1.1.1.1", "1.1.1.1", "2.2.2.2", "1.1.1.1", "3.3.3.3"),
    attack_type = c("ml_anomaly", "ml_anomaly", "ml_anomaly", "ddos", "port_scan"),
    anomaly_score = c(0.66, 0.90, 0.80, 0.70, 0.64),
    ts = c(100, 110, 500, 130, 200)
  )
  meta <- list(threshold = 0.60)
  params <- list(
    score_margin = 0.05,
    alert_min_score = 0.70,
    ml_score_quantile = 0.50,
    dedup_seconds = 60L,
    rules = list(fallback_type = "ml_anomaly")
  )

  out <- idsAiIstd:::.refine_alerts(alerts, meta, params)

  testthat::expect_equal(nrow(out), 3L)
  testthat::expect_true(all(c("ddos", "ml_anomaly") %in% out$attack_type))
  testthat::expect_false(any(out$anomaly_score < 0.70))
  testthat::expect_equal(sum(out$attack_type == "ml_anomaly"), 2L)
})

testthat::test_that(".refine_alerts skips dedup when ts column is absent", {
  alerts <- data.table::data.table(
    src_ip = c("1.1.1.1", "1.1.1.1"),
    attack_type = c("ml_anomaly", "ml_anomaly"),
    anomaly_score = c(0.8, 0.9)
  )
  meta <- list(threshold = 0.5)
  params <- list(
    score_margin = 0,
    alert_min_score = 0,
    ml_score_quantile = 0,
    dedup_seconds = 60L,
    rules = list(fallback_type = "ml_anomaly")
  )

  out <- idsAiIstd:::.refine_alerts(alerts, meta, params)
  testthat::expect_equal(nrow(out), 2L)
  testthat::expect_true(all(c("src_ip", "attack_type", "anomaly_score") %in% names(out)))
})

testthat::test_that("send_alerts writes JSONL and appends additional rows", {
  with_temp_ids_config({
    a1 <- data.table::data.table(
      src_ip = c("1.1.1.1", "2.2.2.2"),
      attack_type = c("ddos", "port_scan"),
      anomaly_score = c(0.91, 0.87)
    )
    a2 <- data.table::data.table(
      src_ip = "3.3.3.3",
      attack_type = "ml_anomaly",
      anomaly_score = 0.75
    )

    n1 <- idsAiIstd::send_alerts(a1, append = FALSE)
    lines1 <- readLines(idsAiIstd:::PATHS$alerts_file, warn = FALSE)
    n2 <- idsAiIstd::send_alerts(a2, append = TRUE)
    lines2 <- readLines(idsAiIstd:::PATHS$alerts_file, warn = FALSE)

    row1 <- jsonlite::fromJSON(lines2[1])
    row3 <- jsonlite::fromJSON(lines2[3])

    testthat::expect_equal(n1, 2L)
    testthat::expect_equal(n2, 1L)
    testthat::expect_length(lines1, 2L)
    testthat::expect_length(lines2, 3L)
    testthat::expect_equal(row1$attack_type, "ddos")
    testthat::expect_equal(row3$src_ip, "3.3.3.3")
  })
})

testthat::test_that("get_attack_meta returns catalog entries and fallback description", {
  known <- idsAiIstd:::get_attack_meta("ddos")
  unknown <- idsAiIstd:::get_attack_meta("never_seen_type")

  testthat::expect_equal(known$label, "DDoS")
  testthat::expect_true(grepl("conn_count_5min", known$rule))
  testthat::expect_equal(unknown$label, "never_seen_type")
  testthat::expect_true(grepl("не описан", unknown$description))
})

testthat::test_that(".fmt_num and .fmt_ts are stable on edge cases", {
  testthat::expect_equal(idsAiIstd:::.fmt_num(NULL), "—")
  testthat::expect_equal(idsAiIstd:::.fmt_num(NA_real_), "—")
  testthat::expect_match(idsAiIstd:::.fmt_num(1234.56, digits = 1L), "1 234.6")

  testthat::expect_equal(idsAiIstd:::.fmt_ts(NULL), "—")
  testthat::expect_match(idsAiIstd:::.fmt_ts(NA_real_), "1970-01-01 00:00:00 UTC")
  testthat::expect_match(idsAiIstd:::.fmt_ts(0), "1970-01-01 00:00:00 UTC")
})

testthat::test_that("explain_alert returns complete payload for multiple attack types", {
  rows <- list(
    ddos = list(
      attack_type = "ddos",
      conn_count_5min = 700,
      dest_port_distinct = 2,
      anomaly_score = 0.95,
      ts = 1710000000,
      src_ip = "10.0.0.1",
      dst_ip = "10.0.0.2",
      src_port = 1111,
      dst_port = 80,
      proto = "tcp",
      attack_score = 4
    ),
    dns = list(
      attack_type = "dns_anomaly",
      query_entropy = 4.4,
      query_length = 55,
      anomaly_score = 0.81,
      ts = 1710000001
    ),
    proxy = list(
      attack_type = "proxy_tunnel",
      service = "socks",
      anomaly_score = 0.79,
      ts = 1710000002
    ),
    ml = list(
      attack_type = "ml_anomaly",
      anomaly_score = 0.77
    ),
    unknown = list(
      attack_type = "unknown_attack_type",
      anomaly_score = 0.66,
      ts = 1710000003
    )
  )

  infos <- lapply(rows, idsAiIstd:::explain_alert)

  for (info in infos) {
    testthat::expect_true(all(c("attack_label", "description", "rule_text", "why", "metrics") %in% names(info)))
    testthat::expect_true(nzchar(info$rule_text))
    testthat::expect_true(is.list(info$metrics))
    testthat::expect_true("Время" %in% names(info$metrics))
  }

  testthat::expect_match(infos$ddos$rule_text, "conn_count_5min")
  testthat::expect_match(infos$dns$why, "query_entropy")
  testthat::expect_match(infos$proxy$why, "service")
  testthat::expect_equal(infos$ml$metrics$`Время`, "—")
  testthat::expect_equal(infos$unknown$attack_label, "unknown_attack_type")
})
