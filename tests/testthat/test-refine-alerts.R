test_that("refine_alerts drops weak ml_anomaly and deduplicates", {
  meta <- list(threshold = 0.7)
  params <- list(
    score_margin = 0,
    alert_min_score = 0,
    ml_score_quantile = 0.5,
    dedup_seconds = 60L,
    rules = list(fallback_type = "ml_anomaly")
  )
  alerts <- data.table::data.table(
    src_ip = c("1.1.1.1", "1.1.1.1", "2.2.2.2"),
    attack_type = c("ml_anomaly", "ml_anomaly", "ddos"),
    anomaly_score = c(0.71, 0.95, 0.99),
    ts = c(100, 110, 200)
  )
  out <- idsAiIstd:::.refine_alerts(alerts, meta, params)
  expect_equal(nrow(out), 2L)
  expect_false(any(out$anomaly_score < 0.75))
  expect_true("ddos" %in% out$attack_type)
})

test_that("refine_alerts applies score margin above threshold", {
  meta <- list(threshold = 0.8)
  params <- list(
    score_margin = 0.05,
    alert_min_score = 0,
    ml_score_quantile = 0,
    dedup_seconds = 0L,
    rules = list(fallback_type = "ml_anomaly")
  )
  alerts <- data.table::data.table(
    src_ip = "1.1.1.1",
    attack_type = "port_scan",
    anomaly_score = 0.84,
    ts = 1
  )
  out <- idsAiIstd:::.refine_alerts(alerts, meta, params)
  expect_equal(nrow(out), 0L)
})
