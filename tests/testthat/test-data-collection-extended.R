with_temp_ids_config <- function(expr) {
  ns <- asNamespace("idsAiIstd")
  old_root <- get("PROJECT_ROOT", envir = ns)
  tmp_root <- tempfile("ids-root-")
  dir.create(tmp_root, recursive = TRUE)
  idsAiIstd::init_ids_config(tmp_root)
  on.exit(idsAiIstd::init_ids_config(old_root), add = TRUE)
  eval.parent(substitute(expr))
}

write_zeek_table <- function(path, fields, rows) {
  lines <- c(
    "#separator \\x09",
    paste0("#fields\t", paste(fields, collapse = "\t")),
    vapply(rows, function(r) paste(r, collapse = "\t"), character(1))
  )
  writeLines(lines, path, useBytes = TRUE)
}

testthat::test_that("load_conn parses conn.log, renames columns, and normalizes numeric fields", {
  zeek_dir <- tempfile("zeek-")
  dir.create(zeek_dir, recursive = TRUE)

  conn_path <- file.path(zeek_dir, "conn.log")
  fields <- c(
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "conn_state", "duration", "orig_bytes", "resp_bytes",
    "missed_bytes", "orig_pkts", "resp_pkts", "history"
  )
  rows <- list(
    c(
      "1710000000.1", "C1", "10.0.0.1", "12345", "10.0.1.1", "80",
      "tcp", "http", "SF", "2.5", "1000", "200", "-", "10", "8", "ShADad"
    ),
    c(
      "1710000001.2", "C2", "10.0.0.2", "53", "8.8.8.8", "53",
      "udp", "dns", "S0", "0.5", "200", "50", "0", "2", "1", "D"
    )
  )
  write_zeek_table(conn_path, fields, rows)

  out <- idsAiIstd:::load_conn(zeek_dir)

  testthat::expect_s3_class(out, "data.table")
  testthat::expect_true(all(c("src_ip", "src_port", "dst_ip", "dst_port") %in% names(out)))
  testthat::expect_equal(out$src_ip, c("10.0.0.1", "10.0.0.2"))
  testthat::expect_equal(out$dst_ip, c("10.0.1.1", "8.8.8.8"))
  testthat::expect_equal(out$src_port, c(12345, 53))
  testthat::expect_equal(out$missed_bytes, c(0, 0))
  testthat::expect_type(out$proto, "character")
  testthat::expect_type(out$service, "character")
})

testthat::test_that("load_conn returns NULL when conn.log is missing", {
  zeek_dir <- tempfile("zeek-empty-")
  dir.create(zeek_dir, recursive = TRUE)
  testthat::expect_null(idsAiIstd:::load_conn(zeek_dir))
})

testthat::test_that("enrich_dns aggregates query features by uid", {
  zeek_dir <- tempfile("zeek-dns-")
  dir.create(zeek_dir, recursive = TRUE)

  dns_path <- file.path(zeek_dir, "dns.log")
  fields <- c("uid", "query")
  rows <- list(
    c("C1", "a.com"),
    c("C1", "very.long.sub.domain.example"),
    c("C2", "x.org")
  )
  write_zeek_table(dns_path, fields, rows)

  out <- idsAiIstd:::enrich_dns(zeek_dir)

  c1 <- out[uid == "C1"]
  c2 <- out[uid == "C2"]

  testthat::expect_equal(nrow(out), 2L)
  testthat::expect_equal(c1$query_length, nchar("very.long.sub.domain.example"))
  testthat::expect_equal(c1$num_labels, 5)
  testthat::expect_gt(c1$query_entropy, 0)
  testthat::expect_equal(c2$query_length, nchar("x.org"))
})

testthat::test_that("enrich_http aggregates uri, user-agent, and status fields", {
  zeek_dir <- tempfile("zeek-http-")
  dir.create(zeek_dir, recursive = TRUE)

  http_path <- file.path(zeek_dir, "http.log")
  fields <- c("uid", "uri", "user_agent", "status_code", "method")
  rows <- list(
    c("H1", "/short", "UA", "200", "GET"),
    c("H1", "/very/very/long/path/for/testing", "Long-Agent", "404", "POST"),
    c("H2", "/x", "X", "500", "PUT")
  )
  write_zeek_table(http_path, fields, rows)

  out <- idsAiIstd:::enrich_http(zeek_dir)
  h1 <- out[uid == "H1"]

  testthat::expect_equal(nrow(out), 2L)
  testthat::expect_equal(h1$uri_length, nchar("/very/very/long/path/for/testing"))
  testthat::expect_equal(h1$ua_length, nchar("Long-Agent"))
  testthat::expect_equal(h1$http_status_code, 404)
  testthat::expect_equal(h1$http_method, "GET")
})

testthat::test_that("enrich_ssl aggregates max SNI length and entropy by uid", {
  zeek_dir <- tempfile("zeek-ssl-")
  dir.create(zeek_dir, recursive = TRUE)

  ssl_path <- file.path(zeek_dir, "ssl.log")
  fields <- c("uid", "server_name")
  rows <- list(
    c("S1", "a.com"),
    c("S1", "malicious-domain-example.biz"),
    c("S2", "b.org")
  )
  write_zeek_table(ssl_path, fields, rows)

  out <- idsAiIstd:::enrich_ssl(zeek_dir)
  s1 <- out[uid == "S1"]

  testthat::expect_equal(nrow(out), 2L)
  testthat::expect_equal(s1$ssl_sni_length, nchar("malicious-domain-example.biz"))
  testthat::expect_gt(s1$ssl_sni_entropy, 0)
})

testthat::test_that("join_uid leaves data unchanged for NULL auxiliary table", {
  conn <- data.table::data.table(uid = c("A", "B"), src_ip = c("1.1.1.1", "2.2.2.2"))

  out <- idsAiIstd:::join_uid(data.table::copy(conn), NULL)
  testthat::expect_equal(out, conn)
})

testthat::test_that("join_uid merges auxiliary columns by uid", {
  conn <- data.table::data.table(uid = c("A", "B"), src_ip = c("1.1.1.1", "2.2.2.2"))
  aux <- data.table::data.table(uid = c("A", "B"), query_length = c(12, 8))

  out <- idsAiIstd:::join_uid(data.table::copy(conn), aux)

  testthat::expect_true("query_length" %in% names(out))
  testthat::expect_equal(out$query_length, c(12, 8))
})

testthat::test_that("process_pcap composes enrichers and adds source_file", {
  testthat::local_mocked_bindings(
    run_zeek = function(pcap_path) "dummy-zeek-dir",
    load_conn = function(zeek_dir) {
      data.table::data.table(uid = "U1", src_ip = "10.0.0.1", dst_ip = "10.0.1.1")
    },
    enrich_dns = function(zeek_dir) {
      data.table::data.table(uid = "U1", query_length = 42)
    },
    enrich_http = function(zeek_dir) {
      data.table::data.table(uid = "U1", uri_length = 120)
    },
    enrich_ssl = function(zeek_dir) {
      data.table::data.table(uid = "U1", ssl_sni_length = 16)
    },
    .package = "idsAiIstd"
  )

  out <- idsAiIstd:::process_pcap("/tmp/example_capture.pcap")

  testthat::expect_equal(nrow(out), 1L)
  testthat::expect_true(all(c("query_length", "uri_length", "ssl_sni_length") %in% names(out)))
  testthat::expect_equal(out$source_file[1], "example_capture.pcap")
})

testthat::test_that("run_zeek returns cached output without invoking Zeek process", {
  with_temp_ids_config({
    pcap <- tempfile(fileext = ".pcap")
    writeBin(as.raw(c(1, 2, 3, 4)), pcap)

    key <- digest::digest(file = pcap, algo = "md5")
    out_dir <- file.path(idsAiIstd:::PATHS$zeek_logs_dir, key)
    dir.create(out_dir, recursive = TRUE)
    file.create(file.path(out_dir, ".done"))

    got <- idsAiIstd:::run_zeek(pcap)
    testthat::expect_equal(got, out_dir)
  })
})

testthat::test_that("run_etl errors when no PCAP files are present", {
  pcap_dir <- tempfile("pcaps-empty-")
  dir.create(pcap_dir, recursive = TRUE)
  out_path <- tempfile(fileext = ".parquet")

  testthat::expect_error(
    idsAiIstd::run_etl(pcap_dir = pcap_dir, out_path = out_path),
    "No PCAPs in:"
  )
})

testthat::test_that("run_etl binds mocked PCAP parts and writes parquet", {
  pcap_dir <- tempfile("pcaps-")
  dir.create(pcap_dir, recursive = TRUE)
  file.create(file.path(pcap_dir, "a.pcap"))
  file.create(file.path(pcap_dir, "b.pcapng"))
  out_path <- tempfile(fileext = ".parquet")

  testthat::local_mocked_bindings(
    process_pcap = function(p) {
      data.table::data.table(
        uid = basename(p),
        src_ip = "10.0.0.1",
        dst_ip = "10.0.1.1",
        ts = 1
      )
    },
    .package = "idsAiIstd"
  )

  out <- idsAiIstd::run_etl(pcap_dir = pcap_dir, out_path = out_path)
  back <- data.table::as.data.table(arrow::read_parquet(out_path))

  testthat::expect_true(file.exists(out_path))
  testthat::expect_equal(nrow(out), 2L)
  testthat::expect_equal(nrow(back), 2L)
  testthat::expect_true(all(c("a.pcap", "b.pcapng") %in% out$uid))
})
