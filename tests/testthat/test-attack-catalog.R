testthat::test_that("explain_alert returns description and rule for ddos", {
  row <- list(
    attack_type = "ddos",
    conn_count_5min = 600,
    dest_port_distinct = 2,
    anomaly_score = 0.91,
    ts = 1e9,
    src_ip = "10.0.0.1",
    dst_ip = "10.0.0.2",
    src_port = 1234,
    dst_port = 80,
    proto = "tcp",
    attack_score = 4
  )
  info <- explain_alert(row)
  testthat::expect_equal(info$attack_label, "DDoS")
  testthat::expect_true(nzchar(info$description))
  testthat::expect_true(nzchar(info$rule_text))
  testthat::expect_true(grepl("500", info$why))
})

testthat::test_that("explain_alert handles ml_anomaly fallback", {
  row <- list(
    attack_type = "ml_anomaly",
    anomaly_score = 0.77,
    conn_count_5min = 1,
    dest_port_distinct = 1,
    unique_dst_ip = 1
  )
  info <- explain_alert(row)
  testthat::expect_match(info$rule_text, "ML")
  testthat::expect_match(info$why, "anomaly_score")
})
