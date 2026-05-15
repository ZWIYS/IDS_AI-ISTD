# =============================================================================
# utils.R — общие утилиты конвейера IDS
# =============================================================================

# Структурированный лог с уровнем
log_msg <- function(level = "INFO", fmt, ...) {
  ts <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
  cat(sprintf("[%s] %-5s %s\n", ts, level, sprintf(fmt, ...)))
}
log_info  <- function(fmt, ...) log_msg("INFO",  fmt, ...)
log_warn  <- function(fmt, ...) log_msg("WARN",  fmt, ...)
log_error <- function(fmt, ...) log_msg("ERROR", fmt, ...)

`%||%` <- function(a, b) if (is.null(a) || length(a) == 0L) b else a

# Безопасное приведение к numeric с заменой NA → 0
safe_num <- function(x) {
  v <- suppressWarnings(as.numeric(x))
  v[is.na(v) | is.infinite(v)] <- 0
  v
}

# Безопасный max: пустой/все NA → default
safe_max <- function(x, default = 0) {
  x <- x[is.finite(x)]
  if (!length(x)) default else max(x)
}

# Энтропия Шеннона строки (для DGA-подобных доменов и SNI)
shannon_entropy <- function(s) {
  if (is.null(s) || is.na(s) || !nzchar(s)) return(0)
  ch <- strsplit(s, "", fixed = TRUE)[[1]]
  p  <- table(ch) / length(ch)
  -sum(p * log2(p))
}
shannon_entropy_v <- function(strs) {
  vapply(strs %||% character(0), shannon_entropy, numeric(1), USE.NAMES = FALSE)
}

# Парсер любого Zeek TSV-лога. Возвращает data.table или NULL.
read_zeek_tsv <- function(path) {
  if (!file.exists(path) || file.info(path)$size == 0) return(NULL)

  con <- file(path, "r")
  on.exit(close(con), add = TRUE)

  fields <- NULL
  data_lines <- character()

  repeat {
    line <- readLines(con, n = 1, warn = FALSE)
    if (length(line) == 0) break
    if (startsWith(line, "#fields")) {
      fields <- strsplit(sub("^#fields\\s+", "", line), "\t", fixed = TRUE)[[1]]
    } else if (startsWith(line, "#")) {
      next
    } else {
      data_lines <- c(data_lines, line)
    }
  }

  if (is.null(fields) || !length(data_lines)) return(NULL)

  dt <- tryCatch(
    data.table::fread(text = data_lines, sep = "\t", header = FALSE,
                      showProgress = FALSE,
                      na.strings = c("-", "(empty)", "(unset)")),
    error = function(e) NULL
  )
  if (is.null(dt) || ncol(dt) != length(fields)) return(NULL)
  data.table::setnames(dt, fields)
  dt
}

# Безопасно достать колонку (или вернуть default нужной длины)
safe_col <- function(dt, name, default = NA, n = NULL) {
  if (is.null(n)) n <- if (is.null(dt)) 0L else nrow(dt)
  if (is.null(dt) || !(name %in% names(dt))) return(rep(default, n))
  dt[[name]]
}

# Загрузка кешированного объекта
load_rds_or_null <- function(path) {
  if (file.exists(path)) readRDS(path) else NULL
}

# Хелпер: source соседнего файла из v2/R/ независимо от cwd
source_sibling <- function(name) {
  here <- tryCatch(dirname(sys.frame(1)$ofile), error = function(e) NULL) %||% getwd()
  source(file.path(here, name), local = FALSE, chdir = TRUE)
}
