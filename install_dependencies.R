#!/usr/bin/env Rscript
# =============================================================================
# install_dependencies.R — быстрая установка R-зависимостей (локально и Docker)
# =============================================================================
# Читает список пакетов из DESCRIPTION (Imports + опционально Suggests).
# На Linux использует бинарники Posit Package Manager (Jammy).
#
# Переменные окружения:
#   INSTALL_SUGGESTS=false  — не ставить Shiny/дашборд (CI по умолчанию)
#   RSPM=<url>              — переопределить CRAN-репозиторий
# =============================================================================

args <- commandArgs(trailingOnly = FALSE)
script <- sub("^--file=", "", grep("^--file=", args, value = TRUE))
ROOT <- if (length(script)) {
  normalizePath(dirname(script), mustWork = FALSE)
} else {
  normalizePath(getwd(), mustWork = FALSE)
}

DESC <- file.path(ROOT, "DESCRIPTION")
if (!file.exists(DESC)) stop("DESCRIPTION not found at: ", DESC)

parse_field <- function(field) {
  d <- read.dcf(DESC)
  if (!field %in% colnames(d)) return(character())
  raw <- trimws(strsplit(d[1, field], ",")[[1]])
  sub("\\s*\\(.*", "", raw)
}

install_suggests <- !identical(
  tolower(Sys.getenv("INSTALL_SUGGESTS", "true")), "false"
)
pkgs <- unique(c(parse_field("Imports"), parse_field("Depends")))
if (install_suggests) pkgs <- unique(c(pkgs, parse_field("Suggests")))
pkgs <- pkgs[!pkgs %in% c("R")]

missing <- pkgs[!vapply(pkgs, requireNamespace, logical(1), quietly = TRUE)]
if (!length(missing)) {
  cat("[OK] All dependencies already installed (", length(pkgs), " packages)\n", sep = "")
  quit(save = "no", status = 0)
}

is_linux <- .Platform$OS.type == "unix" && identical(Sys.info()[["sysname"]], "Linux")
default_rspm <- "https://packagemanager.posit.co/cran/__linux__/jammy/latest"
repos <- Sys.getenv("RSPM", if (is_linux) default_rspm else "https://cloud.r-project.org")
options(repos = c(CRAN = repos))

cat("[INSTALL] ", length(missing), " missing: ", paste(missing, collapse = ", "), "\n", sep = "")
cat("[REPOS]   ", repos, "\n", sep = "")

if (!requireNamespace("pak", quietly = TRUE)) {
  install.packages("pak", repos = "https://cloud.r-project.org")
}
pak::pkg_install(missing, upgrade = FALSE, ask = FALSE)

failed <- missing[!vapply(missing, requireNamespace, logical(1), quietly = TRUE)]
if (length(failed)) stop("Failed to install: ", paste(failed, collapse = ", "))

cat("\n[DONE] Dependencies ready.\n")
