#!/usr/bin/env Rscript
# =============================================================================
# test_basic.R — Минимальные unit-тесты (без зависимости от testthat)
# =============================================================================
# Запуск: Rscript tests/test_basic.R
# Docker: docker run --rm -v "$(pwd):/app" -w /app IMAGE Rscript tests/test_basic.R
# =============================================================================

# --- Setup ------------------------------------------------------------------
.this <- normalizePath(
  sub("^--file=", "", grep("^--file=", commandArgs(FALSE), value = TRUE)),
  mustWork = FALSE
)
V2_ROOT <- normalizePath(file.path(dirname(.this), ".."), mustWork = FALSE)
Sys.setenv(IDS_V2_ROOT = V2_ROOT)

source(file.path(V2_ROOT, "R", "00_config.R"), chdir = TRUE)
source(file.path(V2_ROOT, "R", "utils.R"),     chdir = TRUE)

# --- Tiny test framework ----------------------------------------------------
PASS <- 0L; FAIL <- 0L
check <- function(name, cond) {
  if (isTRUE(cond)) { PASS <<- PASS + 1L; cat("  PASS  ", name, "\n")
  } else            { FAIL <<- FAIL + 1L; cat("  FAIL  ", name, "\n") }
}

# --- Tests ------------------------------------------------------------------
cat("\n[utils.R]\n")
check("safe_num: NA -> 0",        safe_num(NA) == 0)
check("safe_num: Inf -> 0",       safe_num(Inf) == 0)
check("safe_num: char -> num",    safe_num("3.14") == 3.14)
check("safe_max: empty -> 0",     safe_max(integer(0)) == 0)
check("safe_max: NA -> 0",        safe_max(c(NA, NA)) == 0)
check("safe_max: mixed",          safe_max(c(1, NA, 5, Inf)) == 5)
check("shannon_entropy: empty",   shannon_entropy("") == 0)
check("shannon_entropy: 'aaaa'",  shannon_entropy("aaaa") == 0)
check("shannon_entropy: 'ab'",    shannon_entropy("ab") == 1)

cat("\n[00_config.R]\n")
check("PROJECT_ROOT existed",     dir.exists(PROJECT_ROOT))
check("MODEL_PARAMS$ntrees > 0",  MODEL_PARAMS$ntrees > 0)
check("threshold_quant in (0,1)", MODEL_PARAMS$threshold_quant > 0 &&
                                  MODEL_PARAMS$threshold_quant < 1)
check("PATHS$dataset has parquet", grepl("\\.parquet$", PATHS$dataset))

cat("\n[02_feature_engineering.R — classifier]\n")
source(file.path(V2_ROOT, "R", "02_feature_engineering.R"), chdir = TRUE)
source(file.path(V2_ROOT, "R", "04_attack_detection.R"),    chdir = TRUE)

# Synthetic input: 1 row clearly DDoS-like
test_dt <- data.table::data.table(
  src_ip = "10.0.0.1", dst_ip = "10.0.0.2", ts = 0,
  conn_count_5min = 1000, dest_port_distinct = 1, unique_dst_ip = 1,
  duration = 0.01, orig_bytes = 50, resp_bytes = 0, missed_bytes = 0,
  query_length = 0, query_entropy = 0, num_labels = 0, uri_length = 0,
  data_volume_change = 0, ssl_sni_entropy = 0
)
classified <- classify_attacks(test_dt)
check("DDoS pattern -> ddos",     classified$attack_type[1] == "ddos")
check("attack_score >= 3",        classified$attack_score[1] >= 3)

# Port-scan pattern
test_scan <- data.table::copy(test_dt)
test_scan[, `:=`(conn_count_5min = 200, dest_port_distinct = 100,
                 duration = 0.01, orig_bytes = 0, resp_bytes = 0)]
classified <- classify_attacks(test_scan)
check("Scan pattern -> port_scan", classified$attack_type[1] == "port_scan")

test_dns <- data.table::copy(test_dt)
test_dns[, `:=`(conn_count_5min = 2, dest_port_distinct = 1, query_entropy = 4.5,
                query_length = 50)]
classified <- classify_attacks(test_dns)
check("DNS entropy -> dns_anomaly", classified$attack_type[1] == "dns_anomaly")

test_plain <- data.table::copy(test_dt)
test_plain[, `:=`(conn_count_5min = 2, dest_port_distinct = 1, query_entropy = 0,
                  uri_length = 0, ssl_sni_entropy = 0, data_volume_change = 0)]
classified <- classify_attacks(test_plain)
check("No rule match -> ml_anomaly", classified$attack_type[1] == "ml_anomaly")

# --- Summary ----------------------------------------------------------------
cat(sprintf("\n%s  %d passed, %d failed\n",
            if (FAIL == 0) "[OK]" else "[FAIL]", PASS, FAIL))
quit(status = if (FAIL == 0) 0 else 1)
