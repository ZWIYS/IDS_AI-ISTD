# =============================================================================
# ml-training.R — обучение Isolation Forest (tidymodels recipes)
# =============================================================================

#' Обучение Isolation Forest и сохранение модели
#'
#' @param features_path Parquet с признаками.
#' @param model_path Путь к `iforest.rds`.
#' @param meta_path Путь к `model_meta.rds`.
#' @export
train_iforest <- function(features_path = PATHS$features,
                          model_path    = PATHS$model_file,
                          meta_path     = PATHS$meta_file) {
  if (!file.exists(features_path)) stop("Features not found: ", features_path)
  feats <- data.table::as.data.table(arrow::read_parquet(features_path))

  cols_to_keep <- c(NUM_FEATURES, CAT_FEATURES)
  X_raw <- feats[, ..cols_to_keep]

  set.seed(MODEL_PARAMS$seed)
  data_split <- rsample::initial_split(X_raw, prop = 0.8)
  train_data <- rsample::training(data_split)
  valid_data <- rsample::testing(data_split)

  log_info("Tidymodels split: Train=%d, Valid=%d", nrow(train_data), nrow(valid_data))

  ids_recipe <- recipes::recipe(~ ., data = train_data) |>
    recipes::step_impute_median(recipes::all_numeric_predictors()) |>
    recipes::step_string2factor(recipes::all_nominal_predictors()) |>
    recipes::step_novel(recipes::all_nominal_predictors())

  prep_recipe <- recipes::prep(ids_recipe, training = train_data)
  X_train_baked <- recipes::bake(prep_recipe, new_data = NULL)
  X_valid_baked <- recipes::bake(prep_recipe, new_data = valid_data)

  m <- isotree::isolation.forest(
    X_train_baked,
    ntrees         = MODEL_PARAMS$ntrees,
    sample_size    = min(MODEL_PARAMS$sample_size, nrow(X_train_baked)),
    ndim           = MODEL_PARAMS$ndim,
    max_depth      = MODEL_PARAMS$max_depth,
    nthreads       = MODEL_PARAMS$nthreads,
    missing_action = "fail",
    seed           = MODEL_PARAMS$seed
  )

  scores_val <- predict(m, X_valid_baked, type = "score")
  threshold  <- as.numeric(stats::quantile(scores_val, MODEL_PARAMS$threshold_quant))

  saveRDS(m, model_path)
  saveRDS(list(
    threshold     = threshold,
    recipe        = prep_recipe,
    features      = colnames(X_train_baked),
    score_summary = summary(scores_val),
    trained_at    = Sys.time()
  ), meta_path)

  log_info("Trained Isolation Forest with tidymodels recipe. Threshold: %.4f", threshold)
  invisible(m)
}
