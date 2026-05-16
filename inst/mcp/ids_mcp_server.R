#!/usr/bin/env Rscript
# =============================================================================
# MCP-сервер IDS (stdio). Подключение в Cursor: см. inst/mcp/cursor-mcp.json.example
# =============================================================================

args <- commandArgs(trailingOnly = FALSE)
file_arg <- grep("^--file=", args, value = TRUE)
script_dir <- if (length(file_arg)) {
  dirname(normalizePath(sub("^--file=", "", file_arg[1]), mustWork = FALSE))
} else {
  normalizePath(getwd(), mustWork = FALSE)
}

root <- Sys.getenv("IDS_PROJECT_ROOT", "")
if (!nzchar(root)) {
  root <- normalizePath(file.path(script_dir, "..", ".."), mustWork = FALSE)
}
Sys.setenv(IDS_PROJECT_ROOT = root)

if (!requireNamespace("idsAiIstd", quietly = TRUE)) {
  pkg_root <- normalizePath(file.path(script_dir, "..", ".."), mustWork = FALSE)
  if (file.exists(file.path(pkg_root, "DESCRIPTION"))) {
    utils::install.packages(pkg_root, repos = NULL, type = "source", quiet = TRUE)
  }
}
suppressPackageStartupMessages(library(idsAiIstd))
idsAiIstd::init_ids_config(root)

if (!requireNamespace("mcptools", quietly = TRUE)) {
  stop("Пакет mcptools не установлен. install.packages('mcptools')", call. = FALSE)
}
if (!requireNamespace("ellmer", quietly = TRUE)) {
  stop("Пакет ellmer не установлен. install.packages('ellmer')", call. = FALSE)
}

tools_path <- Sys.getenv("IDS_MCP_TOOLS", "")
if (!nzchar(tools_path)) {
  tools_path <- system.file("mcp", "ids_tools.R", package = "idsAiIstd")
}
if (!nzchar(tools_path)) {
  tools_path <- file.path(script_dir, "ids_tools.R")
}
if (!file.exists(tools_path)) {
  stop("ids_tools.R not found: ", tools_path, call. = FALSE)
}

message("[ids-mcp] PROJECT_ROOT=", root)
message("[ids-mcp] tools=", tools_path)

mcptools::mcp_server(
  tools = tools_path,
  session_tools = TRUE,
  type = "stdio"
)
