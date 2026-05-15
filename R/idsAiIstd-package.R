#' @keywords internal
"_PACKAGE"

## usethis namespace: start
#' @importFrom stats predict quantile
## usethis namespace: end

NULL

#' @import data.table
#' @importFrom utils head tail
NULL

.onLoad <- function(libname, pkgname) {
  if (!exists("PATHS", envir = asNamespace(pkgname), inherits = FALSE)) {
    init_ids_config()
  }
  invisible()
}
