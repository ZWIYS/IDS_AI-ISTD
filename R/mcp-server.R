# =============================================================================
# mcp-server.R — запуск MCP-сервера IDS
# =============================================================================

#' Запуск MCP-сервера IDS (stdio)
#'
#' Блокирует процесс R; предназначен для вызова через `Rscript` или конфиг Cursor.
#' Требует Suggests: mcptools, ellmer, jsonlite.
#'
#' @param root Корень проекта (`IDS_PROJECT_ROOT`).
#' @param tools_path Путь к файлу tools (по умолчанию `inst/mcp/ids_tools.R`).
#' @param session_tools Показывать встроенные session-tools mcptools.
#' @return Невидимо (функция не возвращает управление).
#' @export
run_ids_mcp_server <- function(
  root = Sys.getenv("IDS_PROJECT_ROOT", unset = NA),
  tools_path = NULL,
  session_tools = TRUE
) {
  if (is.na(root) || !nzchar(root)) root <- PROJECT_ROOT %||% getwd()
  Sys.setenv(IDS_PROJECT_ROOT = root)
  init_ids_config(root)

  if (!requireNamespace("mcptools", quietly = TRUE)) {
    stop("Install mcptools: install.packages('mcptools')", call. = FALSE)
  }
  if (!requireNamespace("ellmer", quietly = TRUE)) {
    stop("Install ellmer: install.packages('ellmer')", call. = FALSE)
  }

  if (is.null(tools_path) || !nzchar(tools_path)) {
    tools_path <- system.file("mcp", "ids_tools.R", package = "idsAiIstd")
  }
  if (!nzchar(tools_path) || !file.exists(tools_path)) {
    stop("MCP tools file not found", call. = FALSE)
  }

  mcptools::mcp_server(
    tools = tools_path,
    session_tools = isTRUE(session_tools),
    type = "stdio"
  )
}
