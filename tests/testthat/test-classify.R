test_that("classify_attacks detects attack patterns", {
  test_dt <- data.table::data.table(
    src_ip = "10.0.0.1", dst_ip = "10.0.0.2", ts = 0,
    conn_count_5min = 1000, dest_port_distinct = 1, unique_dst_ip = 1,
    duration = 0.01, orig_bytes = 50, resp_bytes = 0, missed_bytes = 0,
    query_length = 0, query_entropy = 0, num_labels = 0, uri_length = 0,
    data_volume_change = 0, ssl_sni_entropy = 0
  )

  classified <- classify_attacks(test_dt)
  expect_equal(classified$attack_type[1], "ddos")
  expect_gte(classified$attack_score[1], 3)

  test_scan <- data.table::copy(test_dt)
  test_scan[, `:=`(conn_count_5min = 200, dest_port_distinct = 100,
                   duration = 0.01, orig_bytes = 0, resp_bytes = 0)]
  expect_equal(classify_attacks(test_scan)$attack_type[1], "port_scan")

  test_dns <- data.table::copy(test_dt)
  test_dns[, `:=`(conn_count_5min = 1, dest_port_distinct = 1,
                  query_entropy = 4.5, query_length = 50)]
  expect_equal(classify_attacks(test_dns)$attack_type[1], "dns_anomaly")

  test_plain <- data.table::copy(test_dt)
  test_plain[, `:=`(conn_count_5min = 1, dest_port_distinct = 1, query_entropy = 0,
                    uri_length = 0, ssl_sni_entropy = 0, data_volume_change = 0)]
  expect_equal(classify_attacks(test_plain)$attack_type[1], "ml_anomaly")
})
