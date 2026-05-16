# =============================================================================
# dashboard-repl.R — интерактивная R-консоль для Shiny-дашборда
# =============================================================================

#' @keywords internal
.repl_forbidden_pattern <- paste(
  c(
    "\\bsystem\\s*\\(", "\\bsystem2\\s*\\(", "\\bunix::",
    "\\bunlink\\s*\\(", "\\bfile\\.remove\\s*\\(", "\\bfile\\.rename\\s*\\(",
    "\\bquit\\s*\\(", "\\bq\\s*\\(", "\\binstall\\.packages\\s*\\(",
    "\\bremove\\.packages\\s*\\(", "\\bdownload\\.file\\s*\\(",
    "\\bsetwd\\s*\\(", "\\bSys\\.setenv\\s*\\("
  ),
  collapse = "|"
)

#' @keywords internal
.repl_code_allowed <- function(code) {
  !grepl(.repl_forbidden_pattern, code, perl = TRUE)
}

#' @keywords internal
.repl_truncate <- function(x, max_chars = 8000L) {
  x <- paste(x, collapse = "\n")
  if (nchar(x) <= max_chars) return(x)
  paste0(substr(x, 1L, max_chars), "\n… [вывод обрезан]")
}

#' @keywords internal
.repl_format_value <- function(val) {
  if (is.null(val)) return("NULL")
  out <- tryCatch(
    capture.output(print(val)),
    error = function(e) capture.output(str(val, max.level = 2))
  )
  .repl_truncate(out)
}

#' @keywords internal
.sync_repl_workspace <- function(env) {
  assign("scored", load_scored(), envir = env)
  assign("alerts", load_alerts(), envir = env)
  meta <- load_model_meta()
  assign("model_meta", meta, envir = env)
  assign("model_threshold", if (is.null(meta)) NA_real_ else meta$threshold %||% NA_real_,
         envir = env)
  invisible(NULL)
}

#' @keywords internal
.create_ids_repl_env <- function() {
  env <- new.env(parent = globalenv())
  if (!exists("PATHS", envir = asNamespace("idsAiIstd"), inherits = FALSE)) {
    init_ids_config()
  }

  assign("PATHS", PATHS, envir = env)
  assign("PROJECT_ROOT", PROJECT_ROOT, envir = env)
  assign("DETECT_PARAMS", DETECT_PARAMS, envir = env)
  assign("MODEL_PARAMS", MODEL_PARAMS, envir = env)

  assign("refresh", function() {
    .sync_repl_workspace(env)
    message("Данные обновлены: scored, alerts, model_meta")
    invisible(NULL)
  }, envir = env)

  assign("help", function() {
    cat(
      paste0(
        "IDS R-консоль — объекты и функции:\n",
        "  PATHS, PROJECT_ROOT, scored, alerts, model_meta, model_threshold\n",
        "  refresh() — перечитать parquet / alerts\n",
        "  run_ids_pipeline(stages, pcap_dir, reset_alerts)\n",
        "  detect(), train_iforest(), build_features(), run_etl()\n",
        "  classify_attacks(dt), send_alerts(dt), list_pcaps()\n",
        "  load_scored(), load_alerts(), get_attack_meta(type)\n"
      )
    )
    invisible(NULL)
  }, envir = env)

  for (fn in c(
    "run_ids_pipeline", "detect", "train_iforest", "build_features", "run_etl",
    "classify_attacks", "classify_attack", "send_alerts", "list_pcaps",
    "load_scored", "load_alerts", "get_attack_meta", "explain_alert",
    "save_uploaded_pcaps", "safe_num", "safe_max"
  )) {
    if (exists(fn, mode = "function", envir = asNamespace("idsAiIstd"), inherits = FALSE)) {
      assign(fn, get(fn, envir = asNamespace("idsAiIstd")), envir = env)
    }
  }

  .sync_repl_workspace(env)
  env
}

#' @keywords internal
.repl_eval <- function(code, env) {
  code <- gsub("\r\n", "\n", trimws(code))
  if (!nzchar(code)) {
    return(list(
      prompt = "",
      output = "",
      value = "",
      error = NULL,
      ok = TRUE
    ))
  }

  if (!.repl_code_allowed(code)) {
    return(list(
      prompt = code,
      output = "",
      value = "",
      error = paste(
        "Команда отклонена политикой безопасности веб-консоли.",
        "Запрещены: system(), unlink(), install.packages(), setwd() и аналоги."
      ),
      ok = FALSE
    ))
  }

  .sync_repl_workspace(env)
  prompt <- code
  stdout <- character()
  value_txt <- ""
  err <- NULL

  result <- tryCatch({
    exprs <- parse(text = code)
    if (!length(exprs)) {
      return(list(prompt = prompt, output = "", value = "", error = NULL, ok = TRUE))
    }
    last_val <- NULL
    for (i in seq_along(exprs)) {
      expr <- exprs[[i]]
      visible <- FALSE
      captured <- utils::capture.output(
        last_val <- withVisible(eval(expr, envir = env, enclos = baseenv())),
        type = "output"
      )
      stdout <- c(stdout, captured)
      if (isTRUE(last_val$visible)) {
        value_txt <- .repl_format_value(last_val$value)
      }
    }
    list(prompt = prompt, output = .repl_truncate(stdout), value = value_txt,
         error = NULL, ok = TRUE)
  }, error = function(e) {
    list(
      prompt = prompt,
      output = .repl_truncate(stdout),
      value = value_txt,
      error = conditionMessage(e),
      ok = FALSE
    )
  })

  result
}

#' @keywords internal
.repl_history_entry_html <- function(entry) {
  prompt <- entry$prompt %||% ""
  out <- entry$output %||% ""
  val <- entry$value %||% ""
  err <- entry$error %||% ""

  blocks <- list(
    shiny::tags$div(
      class = "repl-prompt",
      shiny::tags$span(class = "repl-gt", "> "),
      prompt
    )
  )
  if (nzchar(out)) {
    blocks <- c(blocks, list(shiny::tags$pre(class = "repl-out", out)))
  }
  if (nzchar(val)) {
    blocks <- c(blocks, list(shiny::tags$pre(class = "repl-val", val)))
  }
  if (nzchar(err)) {
    blocks <- c(blocks, list(shiny::tags$pre(class = "repl-err", err)))
  }
  shiny::tags$div(class = "repl-entry", blocks)
}

#' @keywords internal
.render_repl_history <- function(history) {
  if (!length(history)) {
    return(shiny::tags$div(
      class = "repl-console repl-console-empty",
      shiny::tags$p("Интерактивная R-консоль IDS."),
      shiny::tags$p(class = "text-muted small mb-0",
                    "Введите код и нажмите «Выполнить» или Ctrl+Enter. ",
                    "Старт: ", shiny::tags$code("help()"), ", ",
                    shiny::tags$code("nrow(scored)"), ", ",
                    shiny::tags$code("table(alerts$attack_type)"), ".")
    ))
  }
  shiny::tags$div(
    id = "repl_console",
    class = "repl-console",
    lapply(history, .repl_history_entry_html)
  )
}

#' @keywords internal
.repl_console_css <- function() {
  shiny::tags$style(shiny::HTML("
    .repl-console-wrap { margin-top: 8px; }
    .repl-toolbar { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 6px; align-items: center; }
    .repl-console {
      background: #1e1e1e; color: #d4d4d4;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 11px; line-height: 1.4;
      border-radius: 6px; padding: 10px 12px;
      max-height: 260px; overflow-y: auto;
    }
    .repl-console-empty { color: #858585; font-style: normal; }
    .repl-console-empty p { margin: 0 0 6px 0; }
    .repl-entry { margin-bottom: 10px; border-bottom: 1px solid #333; padding-bottom: 8px; }
    .repl-entry:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
    .repl-prompt { color: #4ec9b0; white-space: pre-wrap; word-break: break-word; }
    .repl-gt { color: #569cd6; user-select: none; }
    .repl-out, .repl-val, .repl-err {
      margin: 4px 0 0 0; padding: 0; background: transparent; border: none;
      color: #ce9178; white-space: pre-wrap; word-break: break-word;
    }
    .repl-val { color: #dcdcaa; }
    .repl-err { color: #f48771; }
    #repl_input { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; }
    .mcp-hint { font-size: 0.85rem; }
    .mcp-hint code { font-size: 0.8rem; }
  "))
}

#' @keywords internal
.render_mcp_panel <- function(project_root = PROJECT_ROOT) {
  tools_path <- system.file("mcp", "ids_tools.R", package = "idsAiIstd")
  server_path <- system.file("mcp", "ids_mcp_server.R", package = "idsAiIstd")
  has_mcptools <- requireNamespace("mcptools", quietly = TRUE)
  has_ellmer <- requireNamespace("ellmer", quietly = TRUE)

  cursor_json <- sprintf('{
  "mcpServers": {
    "ids-ai-istd": {
      "command": "Rscript",
      "args": ["%s"],
      "env": {
        "IDS_PROJECT_ROOT": "%s"
      }
    }
  }
}', server_path, project_root)

  shiny::tagList(
    shiny::tags$div(
      class = "mcp-hint",
      shiny::tags$p(
        shiny::tags$strong("MCP (Model Context Protocol)"),
        " позволяет Cursor, Claude Desktop и другим клиентам вызывать ",
        "инструменты IDS (пайплайн, детект, алерты) как функции."
      ),
      shiny::tags$p(
        "Пакеты: ",
        if (has_mcptools) shiny::tags$span(class = "text-success", "mcptools ✓") else shiny::tags$span(class = "text-danger", "mcptools ✗"),
        " · ",
        if (has_ellmer) shiny::tags$span(class = "text-success", "ellmer ✓") else shiny::tags$span(class = "text-danger", "ellmer ✗"),
        if (!has_mcptools || !has_ellmer) {
          shiny::tagList(
            " — ",
            shiny::tags$code("install.packages(c('mcptools', 'ellmer'))")
          )
        }
      ),
      shiny::tags$hr(),
      shiny::tags$h6("1. Cursor / VS Code"),
      shiny::tags$p("Создайте ", shiny::tags$code(".cursor/mcp.json"), " (или отредактируйте глобальный MCP config):"),
      shiny::tags$pre(class = "pipeline-console", style = "max-height: 180px;", cursor_json),
      shiny::tags$h6("2. Запуск сервера вручную"),
      shiny::tags$pre(
        class = "pipeline-console",
        sprintf("IDS_PROJECT_ROOT=%s Rscript %s", project_root, server_path)
      ),
      shiny::tags$h6("3. Инструменты MCP"),
      shiny::tags$ul(
        shiny::tags$li(shiny::tags$code("ids_status"), " — состояние данных и модели"),
        shiny::tags$li(shiny::tags$code("ids_run_pipeline"), " — стадии конвейера"),
        shiny::tags$li(shiny::tags$code("ids_detect"), " — только detect"),
        shiny::tags$li(shiny::tags$code("ids_list_alerts"), " — сводка алертов"),
        shiny::tags$li(shiny::tags$code("ids_explain_alert"), " — пояснение сработки по индексу")
      ),
      shiny::tags$p(class = "text-muted small mb-0",
                    "Файлы: ", shiny::tags$code(server_path), ", ",
                    shiny::tags$code(tools_path))
    )
  )
}
