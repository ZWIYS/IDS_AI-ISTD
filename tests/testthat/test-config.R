test_that("init_ids_config sets paths", {
  cfg <- init_ids_config(PROJECT_ROOT)
  expect_true(dir.exists(cfg$PROJECT_ROOT))
  expect_true(grepl("\\.parquet$", cfg$PATHS$dataset))
  expect_gt(cfg$MODEL_PARAMS$ntrees, 0)
  expect_gt(cfg$MODEL_PARAMS$threshold_quant, 0)
  expect_lt(cfg$MODEL_PARAMS$threshold_quant, 1)
})
