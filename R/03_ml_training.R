# =============================================================================
# 03_ml_training.R — БЛОК 4: Машинное обучение (tidymodels pipeline)
# =============================================================================
local({
  here <- tryCatch(dirname(sys.frame(1)$ofile), error = function(e) getwd())
  source(file.path(here, "00_config.R"),               chdir = TRUE)
  source(file.path(here, "utils.R"),                   chdir = TRUE)
  source(file.path(here, "02_feature_engineering.R"),  chdir = TRUE)
})
ensure_packages(REQUIRED_PKGS)

train_iforest <- function(features_path = PATHS$features,
                          model_path    = PATHS$model_file,
                          meta_path     = PATHS$meta_file) {
  
  if (!file.exists(features_path)) stop("Features not found: ", features_path)
  feats <- data.table::as.data.table(arrow::read_parquet(features_path))
  
  # Оставляем только нужные колонки
  cols_to_keep <- c(NUM_FEATURES, CAT_FEATURES)
  X_raw <- feats[, ..cols_to_keep]
  
  # 1. Сплит данных через rsample (tidymodels)
  set.seed(MODEL_PARAMS$seed)
  data_split <- initial_split(X_raw, prop = 0.8)
  train_data <- training(data_split)
  valid_data <- testing(data_split)
  
  log_info("Tidymodels split: Train=%d, Valid=%d", nrow(train_data), nrow(valid_data))
  
  # 2. Recipe: числовые NA -> медиана; категории уже "unknown" из fill_defaults()
  ids_recipe <- recipe(~ ., data = train_data) |>
    step_impute_median(all_numeric_predictors()) |>
    step_string2factor(all_nominal_predictors()) |>
    step_novel(all_nominal_predictors())
  
  # 3. Обучение рецепта ("запоминание" медиан и уровней факторов)
  prep_recipe <- prep(ids_recipe, training = train_data)
  
  # 4. Применение рецепта к данным (Bake)
  X_train_baked <- bake(prep_recipe, new_data = NULL)
  X_valid_baked <- bake(prep_recipe, new_data = valid_data)
  
  # 5. Обучение Isolation Forest
  m <- isotree::isolation.forest(
    X_train_baked,
    ntrees         = MODEL_PARAMS$ntrees,
    sample_size    = min(MODEL_PARAMS$sample_size, nrow(X_train_baked)),
    ndim           = MODEL_PARAMS$ndim,
    max_depth      = MODEL_PARAMS$max_depth,
    nthreads       = MODEL_PARAMS$nthreads,
    missing_action = "fail", # Рецепт уже устранил все пропуски
    seed           = MODEL_PARAMS$seed
  )
  
  # 6. Вычисление порога на валидационной выборке
  scores_val <- predict(m, X_valid_baked, type = "score")
  threshold  <- as.numeric(stats::quantile(scores_val, MODEL_PARAMS$threshold_quant))
  
  # Сохраняем модель и обученный пайплайн (recipe)
  saveRDS(m, model_path)
  saveRDS(list(
    threshold     = threshold,
    recipe        = prep_recipe,  # <-- Сохраняем рецепт для инференса
    features      = colnames(X_train_baked),
    score_summary = summary(scores_val),
    trained_at    = Sys.time()
  ), meta_path)
  
  log_info("Trained Isolation Forest with tidymodels recipe. Threshold: %.4f", threshold)
}