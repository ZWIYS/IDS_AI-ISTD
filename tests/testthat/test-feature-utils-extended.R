null_coalesce <- get("%||%", envir = asNamespace("idsAiIstd"))

testthat::test_that("%||% falls back for NULL and empty vectors", {
  testthat::expect_equal(null_coalesce(NULL, "fallback"), "fallback")
  testthat::expect_equal(null_coalesce(character(0), "fallback"), "fallback")
  testthat::expect_equal(null_coalesce(integer(0), 42), 42)
})

testthat::test_that("%||% keeps non-empty left value", {
  testthat::expect_equal(null_coalesce("value", "fallback"), "value")
  testthat::expect_equal(null_coalesce(c(1, 2, 3), 0), c(1, 2, 3))
  testthat::expect_equal(null_coalesce(FALSE, TRUE), FALSE)
})

testthat::test_that("shannon_entropy_v works for vectors and empty input", {
  out <- idsAiIstd:::shannon_entropy_v(c("aaaa", "ab", "abcd"))

  testthat::expect_length(out, 3L)
  testthat::expect_equal(out[1], 0)
  testthat::expect_equal(out[2], 1)
  testthat::expect_gt(out[3], out[2])

  testthat::expect_equal(idsAiIstd:::shannon_entropy_v(NULL), numeric(0))
})

testthat::test_that("safe_col returns existing column and default when missing", {
  dt <- data.table::data.table(a = c(10, 20), b = c("x", "y"))

  testthat::expect_equal(idsAiIstd:::safe_col(dt, "a"), c(10, 20))
  testthat::expect_equal(idsAiIstd:::safe_col(dt, "missing", default = 7), c(7, 7))
  testthat::expect_equal(
    idsAiIstd:::safe_col(NULL, "missing", default = "na", n = 3L),
    c("na", "na", "na")
  )
})

testthat::test_that("load_rds_or_null loads existing file and returns NULL for missing", {
  p <- tempfile(fileext = ".rds")
  obj <- list(alpha = 1, beta = "ok")
  saveRDS(obj, p)

  loaded <- idsAiIstd:::load_rds_or_null(p)
  missing <- idsAiIstd:::load_rds_or_null(paste0(p, ".missing"))

  testthat::expect_equal(loaded, obj)
  testthat::expect_null(missing)
})

testthat::test_that("read_zeek_tsv parses a valid Zeek TSV log", {
  p <- tempfile(fileext = ".log")
  lines <- c(
    "#separator \\x09",
    "#set_separator ,",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tservice",
    "1710000000.1\tC1\t10.0.0.1\t12345\thttp",
    "1710000001.2\tC2\t10.0.0.2\t53\tdns"
  )
  writeLines(lines, p, useBytes = TRUE)

  dt <- idsAiIstd:::read_zeek_tsv(p)

  testthat::expect_s3_class(dt, "data.table")
  testthat::expect_equal(
    names(dt),
    c("ts", "uid", "id.orig_h", "id.orig_p", "service")
  )
  testthat::expect_equal(nrow(dt), 2L)
  testthat::expect_equal(dt$uid, c("C1", "C2"))
})

testthat::test_that("read_zeek_tsv returns NULL for malformed or empty files", {
  no_fields <- tempfile(fileext = ".log")
  writeLines(c("#separator \\x09", "1\t2\t3"), no_fields, useBytes = TRUE)

  bad_cols <- tempfile(fileext = ".log")
  writeLines(
    c(
      "#fields\tts\tuid\tid.orig_h\tid.orig_p",
      "1710000000.1\tC1\t10.0.0.1"
    ),
    bad_cols,
    useBytes = TRUE
  )

  empty <- tempfile(fileext = ".log")
  file.create(empty)

  testthat::expect_null(idsAiIstd:::read_zeek_tsv(no_fields))
  testthat::expect_null(idsAiIstd:::read_zeek_tsv(bad_cols))
  testthat::expect_null(idsAiIstd:::read_zeek_tsv(empty))
})

testthat::test_that("add_conn_features creates derived metrics and normalizes values", {
  dt <- data.table::data.table(
    duration = c(2, 0, "bad"),
    orig_bytes = c(100, 30, 5),
    resp_bytes = c(50, 10, 5),
    orig_pkts = c(10, 2, 1),
    resp_pkts = c(5, 0, 2),
    missed_bytes = c(0, 1, NA),
    history = c("ShADad", "", NA)
  )

  out <- idsAiIstd:::add_conn_features(data.table::copy(dt))

  testthat::expect_equal(out$total_bytes, c(150, 40, 10))
  testthat::expect_equal(out$bytes_per_sec, c(75, 0, 0))
  testthat::expect_equal(out$pkt_ratio, c(2, 0, 0.5))
  testthat::expect_equal(out$history_length, c(6, 0, NA))
  testthat::expect_true(all(is.finite(out$missed_bytes)))
})

testthat::test_that("add_conn_features adds missing input columns", {
  dt <- data.table::data.table(
    duration = c(1, 2),
    orig_bytes = c(10, 20),
    resp_bytes = c(5, 10)
  )

  out <- idsAiIstd:::add_conn_features(data.table::copy(dt))

  needed <- c("orig_pkts", "resp_pkts", "missed_bytes")
  testthat::expect_true(all(needed %in% names(out)))
  testthat::expect_equal(out$orig_pkts, c(0, 0))
  testthat::expect_equal(out$resp_pkts, c(0, 0))
  testthat::expect_equal(out$missed_bytes, c(0, 0))
})

testthat::test_that("add_window_features computes rolling aggregates by src and bucket", {
  dt <- data.table::data.table(
    src_ip = c("10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.2"),
    dst_ip = c("10.0.1.1", "10.0.1.2", "10.0.1.1", "10.0.2.1"),
    dst_port = c(80, 443, 80, 53),
    ts = c(10, 20, 350, 15),
    total_bytes = c(100, 200, 600, 50)
  )

  out <- idsAiIstd:::add_window_features(data.table::copy(dt), win = 300L)

  testthat::expect_equal(out$conn_count_5min, c(2, 2, 1, 1))
  testthat::expect_equal(out$dest_port_distinct, c(2, 2, 1, 1))
  testthat::expect_equal(out$unique_dst_ip, c(2, 2, 1, 1))
  testthat::expect_equal(out$bytes_5min, c(300, 300, 600, 50))
  testthat::expect_equal(out$data_volume_change, c(0, 0, 100, 0))
})

testthat::test_that("add_window_features leaves data untouched without required columns", {
  dt_no_src <- data.table::data.table(ts = c(1, 2), total_bytes = c(10, 20))
  out_no_src <- idsAiIstd:::add_window_features(data.table::copy(dt_no_src), win = 60L)
  testthat::expect_equal(names(out_no_src), names(dt_no_src))
  testthat::expect_equal(nrow(out_no_src), nrow(dt_no_src))

  dt_no_ts <- data.table::data.table(src_ip = c("1.1.1.1"), total_bytes = 10)
  out_no_ts <- idsAiIstd:::add_window_features(data.table::copy(dt_no_ts), win = 60L)
  testthat::expect_equal(names(out_no_ts), names(dt_no_ts))
  testthat::expect_equal(nrow(out_no_ts), nrow(dt_no_ts))
})

testthat::test_that("fill_defaults injects missing features and normalizes categories", {
  dt <- data.table::data.table(
    duration = c("2.5", "bad"),
    proto = c("tcp", ""),
    service = c(NA_character_, "dns")
  )

  out <- idsAiIstd:::fill_defaults(data.table::copy(dt))

  testthat::expect_true(all(idsAiIstd:::NUM_FEATURES %in% names(out)))
  testthat::expect_true(all(idsAiIstd:::CAT_FEATURES %in% names(out)))
  testthat::expect_equal(out$duration, c(2.5, 0))
  testthat::expect_equal(out$proto, c("tcp", "unknown"))
  testthat::expect_equal(out$service, c("unknown", "dns"))
  testthat::expect_equal(out$conn_state, c("unknown", "unknown"))
})

testthat::test_that("build_features creates parquet with engineered columns", {
  in_path <- tempfile(fileext = ".parquet")
  out_path <- tempfile(fileext = ".parquet")

  raw_dt <- data.table::data.table(
    uid = c("A1", "A2"),
    src_ip = c("10.0.0.1", "10.0.0.1"),
    dst_ip = c("10.0.1.1", "10.0.1.2"),
    dst_port = c(80, 443),
    ts = c(100, 140),
    duration = c(2, 4),
    orig_bytes = c(1000, 1200),
    resp_bytes = c(100, 300),
    missed_bytes = c(0, 0),
    orig_pkts = c(10, 12),
    resp_pkts = c(5, 6),
    history = c("ShADad", "ShADad"),
    proto = c("tcp", "tcp"),
    service = c("http", "http"),
    conn_state = c("SF", "SF")
  )
  arrow::write_parquet(raw_dt, in_path)

  built <- idsAiIstd::build_features(in_path = in_path, out_path = out_path)
  stored <- data.table::as.data.table(arrow::read_parquet(out_path))

  testthat::expect_true(file.exists(out_path))
  testthat::expect_equal(nrow(built), 2L)
  testthat::expect_equal(nrow(stored), 2L)
  testthat::expect_true(all(idsAiIstd:::NUM_FEATURES %in% names(stored)))
  testthat::expect_true(all(idsAiIstd:::CAT_FEATURES %in% names(stored)))
  testthat::expect_true(all(stored$proto != ""))
})
