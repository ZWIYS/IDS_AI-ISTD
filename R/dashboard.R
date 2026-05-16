# =============================================================================
# dashboard.R — Shiny dashboard
# =============================================================================

#' @keywords internal
.check_dashboard_deps <- function() {
  for (p in c("shiny", "DT", "plotly", "bslib")) {
    if (!requireNamespace(p, quietly = TRUE)) {
      stop("Package ", p, " required. Install with: install.packages('", p, "')",
           call. = FALSE)
    }
  }
}

#' @keywords internal
load_scored <- function() {
  if (!file.exists(PATHS$scored)) return(data.table::data.table())
  data.table::as.data.table(arrow::read_parquet(PATHS$scored))
}

#' @keywords internal
load_model_meta <- function() {
  .load_model_meta()
}

#' @keywords internal
.attack_palette <- function(types) {
  cols <- c(
    ddos = "#e74c3c", port_scan = "#9b59b6", exfiltration = "#c0392b",
    botnet = "#8e44ad", dos = "#d35400", dns_anomaly = "#2980b9",
    http_anomaly = "#16a085", ssl_anomaly = "#27ae60",
    traffic_spike = "#f39c12", proxy_tunnel = "#7f8c8d",
    ml_anomaly = "#95a5a6"
  )
  out <- cols[types]
  out[is.na(out)] <- "#bdc3c7"
  out
}

#' @keywords internal
.pipeline_console_css <- function() {
  shiny::tags$style(shiny::HTML("
    .pipeline-console-wrap { margin-top: 8px; }
    .pipeline-console-toolbar {
      display: flex; gap: 6px; align-items: center; margin-bottom: 6px;
    }
    .pipeline-console {
      background: #1e1e1e;
      color: #d4d4d4;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 11px;
      line-height: 1.45;
      border-radius: 6px;
      padding: 10px 12px;
      max-height: 220px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .pipeline-console .log-line { margin: 0 0 2px 0; }
    .pipeline-console .log-err { color: #f48771; }
    .pipeline-console .log-warn { color: #dcdcaa; }
    .pipeline-console .log-ok { color: #4ec9b0; }
    .pipeline-console .log-stage { color: #569cd6; font-weight: 600; }
    .pipeline-console .log-muted { color: #858585; }
    .pipeline-console-empty { color: #858585; font-style: italic; }
  "))
}

#' @keywords internal
.format_console_line <- function(ln) {
  cls <- "log-line"
  if (grepl("^ERROR", ln, ignore.case = TRUE)) {
    cls <- paste(cls, "log-err")
  } else if (grepl("WARNING|WARN", ln, ignore.case = TRUE)) {
    cls <- paste(cls, "log-warn")
  } else if (grepl("Готово|^OK$|complete|done in", ln, ignore.case = TRUE)) {
    cls <- paste(cls, "log-ok")
  } else if (grepl("^==== STAGE:", ln)) {
    cls <- paste(cls, "log-stage")
  } else if (grepl("^Запуск", ln)) {
    cls <- paste(cls, "log-muted")
  }
  shiny::tags$div(class = cls, ln)
}

#' @keywords internal
.render_pipeline_console <- function(log_text, filter = "all") {
  if (!nzchar(log_text %||% "")) {
    return(shiny::tags$div(
      class = "pipeline-console pipeline-console-empty",
      "Консоль готова. Запустите анализ PCAP — здесь появится пошаговый лог Zeek и ML."
    ))
  }
  lines <- strsplit(log_text, "\n", fixed = TRUE)[[1]]
  lines <- lines[nzchar(lines)]
  if (filter == "errors") {
    lines <- lines[grepl("ERROR|ошибк", lines, ignore.case = TRUE)]
    if (!length(lines)) {
      return(shiny::tags$div(
        class = "pipeline-console pipeline-console-empty",
        "Ошибок в текущем логе нет."
      ))
    }
  }
  shiny::tags$div(
    id = "pipeline_console",
    class = "pipeline-console",
    lapply(lines, .format_console_line)
  )
}

#' @keywords internal
load_alerts <- function() {
  if (!file.exists(PATHS$alerts_file) || file.info(PATHS$alerts_file)$size == 0) {
    return(data.table::data.table())
  }
  lines <- readLines(PATHS$alerts_file, warn = FALSE)
  lines <- lines[nzchar(lines)]
  if (!length(lines)) return(data.table::data.table())
  dt <- data.table::rbindlist(lapply(lines, jsonlite::fromJSON), fill = TRUE)
  dt[, alert_id := seq_len(.N)]
  dt
}

#' @keywords internal
.alert_card_css <- function() {
  shiny::tags$style(shiny::HTML("
    .alert-list { max-height: 520px; overflow-y: auto; padding-right: 4px; }
    .alert-card {
      border: 1px solid #dee2e6;
      border-radius: 8px;
      padding: 10px 12px;
      margin-bottom: 8px;
      cursor: pointer;
      transition: border-color .15s, box-shadow .15s;
      background: #fff;
    }
    .alert-card:hover { border-color: #3498db; box-shadow: 0 2px 6px rgba(0,0,0,.08); }
    .alert-card.active { border-color: #2c3e50; box-shadow: 0 0 0 2px rgba(44,62,80,.15); }
    .alert-card .atype { font-weight: 600; font-size: 0.95rem; }
    .alert-card .meta { font-size: 0.8rem; color: #6c757d; margin-top: 4px; }
    .alert-detail-section { margin-bottom: 1rem; }
    .alert-detail-section h6 {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: .04em;
      color: #6c757d;
      margin-bottom: 0.35rem;
    }
    .metric-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 16px; font-size: 0.9rem; }
    .metric-grid dt { color: #6c757d; font-weight: normal; margin: 0; }
    .metric-grid dd { margin: 0 0 4px 0; font-weight: 500; }
    .rule-box, .why-box {
      background: #f8f9fa;
      border-left: 3px solid #3498db;
      padding: 10px 12px;
      border-radius: 4px;
      font-size: 0.9rem;
      line-height: 1.45;
    }
    .why-box { border-left-color: #e67e22; }
  "))
}

#' @keywords internal
.render_alert_card <- function(row, active = FALSE) {
  meta <- get_attack_meta(row$attack_type)
  score <- safe_num(row$anomaly_score)
  shiny::tags$div(
    class = paste("alert-card", if (active) "active"),
    onclick = sprintf(
      "Shiny.setInputValue('alert_click', %d, {priority: 'event'})",
      as.integer(row$alert_id)
    ),
    shiny::tags$div(class = "atype", meta$label),
    shiny::tags$div(
      class = "meta",
      sprintf(
        "%s → %s:%s · score %s · %s",
        row$src_ip %||% "—",
        row$dst_ip %||% "—",
        row$dst_port %||% "—",
        format(round(score, 4), nsmall = 4),
        .fmt_ts(row$ts)
      )
    )
  )
}

#' @keywords internal
.render_alert_detail <- function(row) {
  if (is.null(row) || !length(row)) {
    return(shiny::tags$div(
      class = "text-muted p-3",
      shiny::icon("hand-pointer"),
      " Выберите алерт в списке слева, чтобы увидеть детали сработки."
    ))
  }

  info <- explain_alert(row)
  metrics_ui <- shiny::tags$dl(
    class = "metric-grid",
    lapply(names(info$metrics), function(nm) {
      shiny::tagList(
        shiny::tags$dt(nm),
        shiny::tags$dd(info$metrics[[nm]])
      )
    })
  )

  shiny::tagList(
    shiny::tags$div(
      class = "d-flex justify-content-between align-items-start mb-3",
      shiny::tags$div(
        shiny::tags$h5(info$attack_label, class = "mb-1"),
        shiny::tags$span(
          class = "badge bg-secondary",
          as.character(row$attack_type %||% "—")
        ),
        shiny::tags$span(
          class = "badge bg-danger ms-1",
          paste0("score ", format(round(safe_num(row$anomaly_score), 4), nsmall = 4))
        )
      )
    ),
    shiny::tags$div(
      class = "alert-detail-section",
      shiny::tags$h6("Описание атаки"),
      shiny::tags$p(info$description, class = "mb-0")
    ),
    shiny::tags$div(
      class = "alert-detail-section",
      shiny::tags$h6("Правило детектирования"),
      shiny::tags$div(class = "rule-box", info$rule_text)
    ),
    shiny::tags$div(
      class = "alert-detail-section",
      shiny::tags$h6("Почему помечено так"),
      shiny::tags$div(class = "why-box", info$why)
    ),
    shiny::tags$div(
      class = "alert-detail-section",
      shiny::tags$h6("Параметры сессии"),
      metrics_ui
    )
  )
}

#' UI и server Shiny-приложения IDS
#'
#' @return Объект `shiny.appobj`.
#' @export
ids_dashboard_app <- function() {
  .check_dashboard_deps()

  ui <- bslib::page_sidebar(
    title = "IoT IDS — Dashboard",
    theme = bslib::bs_theme(bootswatch = "flatly"),
    .alert_card_css(),
    .pipeline_console_css(),
    shiny::tags$script(shiny::HTML("
      Shiny.addCustomMessageHandler('idsScrollConsole', function() {
        var el = document.getElementById('pipeline_console');
        if (el) el.scrollTop = el.scrollHeight;
      });
    ")),
    sidebar = bslib::sidebar(
      width = 380,
      bslib::card(
        bslib::card_header("Загрузка PCAP"),
        shiny::fileInput(
          "pcap_upload", NULL,
          multiple = TRUE, buttonLabel = "Выбрать…", placeholder = "не выбрано",
          accept = c(".pcap", ".pcapng", ".gz", ".PCAP", ".PCAPNG")
        ),
        shiny::checkboxInput("replace_pcaps", "Заменить ранее загруженные", TRUE),
        shiny::actionButton("run_pipeline", "Запустить анализ",
                          class = "btn-primary", icon = shiny::icon("play")),
        shiny::tags$small(class = "text-muted",
                          "Форматы: .pcap, .pcapng, .pcap.gz."),
        shiny::tags$div(
          class = "pipeline-console-wrap",
          shiny::tags$div(
            class = "pipeline-console-toolbar",
            shiny::selectInput(
              "log_filter", NULL,
              choices = c(
                "Весь лог" = "all",
                "Только ошибки" = "errors"
              ),
              width = "140px"
            ),
            shiny::actionButton(
              "clear_log", "Очистить",
              class = "btn-sm btn-outline-secondary",
              icon = shiny::icon("eraser")
            ),
            shiny::downloadButton(
              "download_log", "Скачать",
              class = "btn-sm btn-outline-secondary"
            )
          ),
          shiny::uiOutput("pipeline_console")
        ),
        shiny::tags$hr(),
        shiny::textOutput("pcap_queue")
      ),
      shiny::actionButton("refresh", "Обновить дашборд", icon = shiny::icon("rotate")),
      shiny::selectInput("attack_filter", "Тип атаки:", choices = NULL, multiple = TRUE),
      shiny::sliderInput("score_min", "Min anomaly score:",
                         min = 0, max = 1, value = 0, step = 0.01)
    ),
    bslib::layout_columns(
      bslib::value_box(title = "Сессий",       value = shiny::textOutput("n_sessions"), theme = "primary"),
      bslib::value_box(title = "Аномалий",     value = shiny::textOutput("n_anom"),     theme = "warning"),
      bslib::value_box(title = "Алертов",      value = shiny::textOutput("n_alerts"),   theme = "danger"),
      bslib::value_box(title = "Уник. src_ip", value = shiny::textOutput("n_src"),      theme = "info")
    ),
    bslib::navset_card_tab(
      bslib::nav_panel(
        "Распределение score",
        plotly::plotlyOutput("hist", height = "380px")
      ),
      bslib::nav_panel(
        "Аномалии во времени",
        plotly::plotlyOutput("anom_ts", height = "380px")
      ),
      bslib::nav_panel(
        "Атаки во времени",
        plotly::plotlyOutput("ts", height = "380px")
      ),
      bslib::nav_panel(
        "Типы атак",
        plotly::plotlyOutput("attack_mix", height = "380px")
      ),
      bslib::nav_panel(
        "Топ src_ip",
        plotly::plotlyOutput("topip", height = "380px")
      )
    ),
    bslib::card(
      bslib::card_header("Алерты"),
      bslib::navset_card_tab(
        bslib::nav_panel(
          "Карточки",
          bslib::layout_columns(
            col_widths = c(4, 8),
            shiny::uiOutput("alert_cards"),
            bslib::card(
              bslib::card_header("Детали сработки"),
              shiny::uiOutput("alert_detail")
            )
          )
        ),
        bslib::nav_panel("Таблица", DT::DTOutput("alerts_tbl"))
      )
    )
  )

  server <- function(input, output, session) {
    rv <- shiny::reactiveValues(
      scored = load_scored(),
      alerts = load_alerts(),
      pipeline_log = "",
      selected_alert_id = NULL
    )
    pipeline_busy <- shiny::reactiveVal(FALSE)
    model_meta <- shiny::reactive(load_model_meta())

    refresh_dashboard <- function() {
      rv$scored <- load_scored()
      rv$alerts <- load_alerts()
      types <- sort(unique(rv$alerts$attack_type))
      shiny::updateSelectInput(session, "attack_filter", choices = types, selected = types)
      smax <- max(rv$scored$anomaly_score %||% 1, na.rm = TRUE)
      if (is.finite(smax) && smax > 0) {
        shiny::updateSliderInput(
          session, "score_min",
          max = round(smax, 2),
          step = max(0.001, round(smax / 200, 4))
        )
      }
    }

    shiny::observeEvent(input$refresh, refresh_dashboard(),
                        ignoreNULL = FALSE, ignoreInit = FALSE)

    output$pcap_queue <- shiny::renderText({
      files <- list_pcaps()
      if (!length(files)) return("Очередь пуста — загрузите PCAP")
      paste0(length(files), " файл(ов):\n", paste0(" • ", basename(files), collapse = "\n"))
    })

    output$pipeline_console <- shiny::renderUI({
      .render_pipeline_console(rv$pipeline_log, input$log_filter %||% "all")
    })

    shiny::observeEvent(input$clear_log, {
      rv$pipeline_log <- ""
    })

    output$download_log <- shiny::downloadHandler(
      filename = function() {
        paste0("ids-pipeline-", format(Sys.time(), "%Y%m%d-%H%M%S"), ".log")
      },
      content = function(file) {
        writeLines(rv$pipeline_log %||% "", file, useBytes = TRUE)
      }
    )

    shiny::observe({
      shiny::req(nzchar(rv$pipeline_log %||% ""))
      session$sendCustomMessage("idsScrollConsole", list())
    })

    shiny::observeEvent(input$run_pipeline, {
      if (pipeline_busy()) {
        shiny::showNotification("Анализ уже выполняется", type = "warning")
        return()
      }
      if (is.null(input$pcap_upload) || !nrow(input$pcap_upload)) {
        existing <- list_pcaps()
        if (!length(existing)) {
          shiny::showNotification("Сначала загрузите PCAP", type = "error")
          return()
        }
      }

      pipeline_busy(TRUE)
      rv$pipeline_log <- paste0(
        "[", format(Sys.time(), "%H:%M:%S"), "] Запуск конвейера IDS…\n"
      )
      shiny::updateActionButton(session, "run_pipeline", label = "Выполняется…")

      shiny::withProgress(message = "Анализ PCAP", value = 0, {
        log_file <- tempfile()
        result <- tryCatch({
          if (!is.null(input$pcap_upload) && nrow(input$pcap_upload)) {
            shiny::incProgress(0.1, detail = "Сохранение PCAP")
            save_uploaded_pcaps(input$pcap_upload, replace = isTRUE(input$replace_pcaps))
          }
          shiny::incProgress(0.2, detail = "Zeek + ML pipeline")
          sink(log_file, type = "output")
          on.exit(sink(), add = TRUE)
          run_ids_pipeline(
            pcap_dir     = PATHS$pcap_upload_dir,
            reset_alerts = isTRUE(input$replace_pcaps)
          )
          "OK"
        }, error = function(e) {
          structure(e$message, class = "error")
        })
      })

      log_lines <- if (file.exists(log_file)) readLines(log_file, warn = FALSE) else character()

      if (inherits(result, "error")) {
        summary_line <- paste("ERROR:", result)
      } else {
        refresh_dashboard()
        meta <- model_meta()
        n_al <- nrow(rv$alerts)
        n_sc <- nrow(rv$scored)
        n_an <- sum(rv$scored$is_anomaly %||% FALSE, na.rm = TRUE)
        thr <- if (!is.null(meta)) meta$threshold else NA
        ml_n <- sum(rv$alerts$attack_type == "ml_anomaly", na.rm = TRUE)
        summary_line <- sprintf(
          paste0(
            "Готово. Сессий: %s, аномалий ML: %s, алертов: %s",
            " (ML-аномалий: %s). Порог модели: %s"
          ),
          format(n_sc, big.mark = " "),
          format(n_an, big.mark = " "),
          format(n_al, big.mark = " "),
          format(ml_n, big.mark = " "),
          if (is.finite(thr)) format(round(thr, 4), nsmall = 4) else "—"
        )
      }

      rv$pipeline_log <- paste(
        c(rv$pipeline_log, log_lines, summary_line),
        collapse = "\n"
      )
      pipeline_busy(FALSE)
      shiny::updateActionButton(session, "run_pipeline", label = "Запустить анализ")

      if (inherits(result, "error")) {
        shiny::showNotification(paste("Ошибка:", result), type = "error", duration = NULL)
      } else {
        n_al <- nrow(rv$alerts)
        ml_n <- sum(rv$alerts$attack_type == "ml_anomaly", na.rm = TRUE)
        shiny::showNotification(
          sprintf("Анализ завершён: %d алерт(ов), из них ML-аномалий: %d", n_al, ml_n),
          type = "message"
        )
      }
    })

    filtered_alerts <- shiny::reactive({
      a <- rv$alerts
      if (!nrow(a)) return(a)
      if (length(input$attack_filter)) {
        a <- a[attack_type %in% input$attack_filter]
      }
      if (!is.null(input$score_min)) {
        a <- a[anomaly_score >= input$score_min]
      }
      if (nrow(a) && "ts" %in% names(a)) {
        data.table::setorder(a, -ts)
      }
      a
    })

    shiny::observeEvent(filtered_alerts(), {
      a <- filtered_alerts()
      if (!nrow(a)) {
        rv$selected_alert_id <- NULL
        return()
      }
      if (is.null(rv$selected_alert_id) ||
          !(rv$selected_alert_id %in% a$alert_id)) {
        rv$selected_alert_id <- a$alert_id[1L]
      }
    }, ignoreNULL = FALSE)

    shiny::observeEvent(input$alert_click, {
      shiny::req(input$alert_click)
      rv$selected_alert_id <- as.integer(input$alert_click)
    })

    selected_alert_row <- shiny::reactive({
      a <- filtered_alerts()
      if (!nrow(a) || is.null(rv$selected_alert_id)) return(NULL)
      row <- a[alert_id == rv$selected_alert_id]
      if (!nrow(row)) return(NULL)
      as.list(row[1L])
    })

    output$alert_cards <- shiny::renderUI({
      a <- filtered_alerts()
      if (!nrow(a)) {
        return(shiny::tags$div(class = "text-muted p-2", "Нет алертов по выбранным фильтрам"))
      }
      shiny::tagList(
        shiny::tags$div(class = "text-muted small mb-2", sprintf("%d алерт(ов)", nrow(a))),
        shiny::tags$div(
          class = "alert-list",
          lapply(seq_len(nrow(a)), function(i) {
            .render_alert_card(
              a[i],
              active = identical(a$alert_id[i], rv$selected_alert_id)
            )
          })
        )
      )
    })

    output$alert_detail <- shiny::renderUI({
      .render_alert_detail(selected_alert_row())
    })

    output$n_sessions <- shiny::renderText(format(nrow(rv$scored), big.mark = " "))
    output$n_anom <- shiny::renderText(format(sum(rv$scored$is_anomaly %||% FALSE, na.rm = TRUE),
                                             big.mark = " "))
    output$n_alerts <- shiny::renderText(format(nrow(filtered_alerts()), big.mark = " "))
    output$n_src <- shiny::renderText({
      a <- filtered_alerts()
      if (!nrow(a)) "0" else format(data.table::uniqueN(a$src_ip), big.mark = " ")
    })

    model_threshold <- shiny::reactive({
      m <- model_meta()
      if (is.null(m)) return(NA_real_)
      as.numeric(m$threshold %||% NA_real_)
    })

    output$hist <- plotly::renderPlotly({
      shiny::req(nrow(rv$scored) > 0)
      s <- rv$scored
      thr <- model_threshold()
      normal <- s[is_anomaly != TRUE | is.na(is_anomaly)]
      anom <- s[is_anomaly == TRUE]

      p <- plotly::plot_ly() |>
        plotly::add_trace(
          data = normal, x = ~anomaly_score, type = "histogram",
          name = "Норма", nbinsx = 50, marker = list(color = "#3498db", opacity = 0.65)
        ) |>
        plotly::add_trace(
          data = anom, x = ~anomaly_score, type = "histogram",
          name = "Аномалия", nbinsx = 50, marker = list(color = "#e74c3c", opacity = 0.75)
        )

      n_an <- nrow(anom)
      pct <- if (nrow(s)) round(100 * n_an / nrow(s), 2) else 0
      layout_args <- list(
        title = sprintf(
          "Распределение anomaly_score (%s сессий, %.2f%% аномалий)",
          format(nrow(s), big.mark = " "), pct
        ),
        barmode = "overlay",
        xaxis = list(title = "anomaly_score"),
        yaxis = list(title = "число сессий"),
        legend = list(orientation = "h", y = 1.12)
      )
      if (is.finite(thr)) {
        layout_args$shapes <- list(list(
          type = "line", x0 = thr, x1 = thr, y0 = 0, y1 = 1,
          yref = "paper", line = list(color = "#2c3e50", width = 2, dash = "dash")
        ))
        layout_args$annotations <- list(list(
          x = thr, y = 1, yref = "paper", text = sprintf("порог %.4f", thr),
          showarrow = FALSE, xanchor = "left", font = list(size = 11)
        ))
      }
      p |>
        plotly::layout(layout_args) |>
        plotly::config(displayModeBar = TRUE)
    })

    output$anom_ts <- plotly::renderPlotly({
      shiny::req(nrow(rv$scored) > 0, "ts" %in% names(rv$scored))
      s <- data.table::copy(rv$scored)
      s[, t := as.POSIXct(safe_num(ts), origin = "1970-01-01", tz = "UTC")]
      s[, bucket := as.POSIXct(floor(as.numeric(t) / 60) * 60,
                               origin = "1970-01-01", tz = "UTC")]
      g <- s[, .(
        sessions = .N,
        anomalies = sum(is_anomaly == TRUE, na.rm = TRUE),
        mean_score = mean(anomaly_score, na.rm = TRUE)
      ), by = bucket]
      g[, rate_pct := ifelse(sessions > 0, 100 * anomalies / sessions, 0)]

      plotly::plot_ly(g, x = ~bucket) |>
        plotly::add_bars(
          y = ~sessions, name = "Сессий/мин",
          marker = list(color = "#bdc3c7"),
          text = ~paste("сессий:", sessions), hoverinfo = "text+x"
        ) |>
        plotly::add_trace(
          y = ~anomalies, type = "scatter", mode = "lines+markers",
          name = "Аномалий/мин", line = list(color = "#e74c3c", width = 2),
          text = ~paste("аномалий:", anomalies, "| доля:", round(rate_pct, 1), "%"),
          hoverinfo = "text+x"
        ) |>
        plotly::layout(
          title = "Динамика сессий и ML-аномалий по минутам",
          xaxis = list(title = "время (UTC)"),
          yaxis = list(title = "количество"),
          legend = list(orientation = "h", y = 1.1)
        )
    })

    output$ts <- plotly::renderPlotly({
      a <- filtered_alerts()
      shiny::req(nrow(a) > 0)
      a <- data.table::copy(a)
      a[, t := as.POSIXct(safe_num(ts), origin = "1970-01-01", tz = "UTC")]
      a[, bucket := as.POSIXct(floor(as.numeric(t) / 60) * 60,
                               origin = "1970-01-01", tz = "UTC")]
      a[, attack_label := vapply(attack_type, function(tp) {
        get_attack_meta(tp)$label
      }, character(1))]
      g <- a[, .N, by = .(bucket, attack_type, attack_label)]
      types <- unique(g$attack_type)
      pal <- .attack_palette(types)

      p <- plotly::plot_ly()
      for (tp in types) {
        sub <- g[attack_type == tp]
        p <- p |>
          plotly::add_trace(
            data = sub, x = ~bucket, y = ~N, type = "bar",
            name = sub$attack_label[1],
            marker = list(color = pal[tp]),
            text = ~paste0(attack_label, ": ", N),
            hoverinfo = "text+x"
          )
      }
      p |>
        plotly::layout(
          barmode = "stack",
          title = sprintf("Алерты по типам (%d после фильтров)", nrow(a)),
          xaxis = list(title = "время (UTC)"),
          yaxis = list(title = "алертов / мин"),
          legend = list(orientation = "h", y = 1.12)
        )
    })

    output$attack_mix <- plotly::renderPlotly({
      a <- filtered_alerts()
      shiny::req(nrow(a) > 0)
      g <- a[, .N, by = attack_type][order(-N)]
      g[, label := vapply(attack_type, function(tp) {
        get_attack_meta(tp)$label
      }, character(1))]
      g[, pct := round(100 * N / sum(N), 1)]
      g[, hover := paste0(label, ": ", N, " (", pct, "%)")]

      plotly::plot_ly(
        g, labels = ~label, values = ~N, type = "pie",
        text = ~hover, hoverinfo = "text",
        marker = list(colors = .attack_palette(g$attack_type), line = list(color = "#fff", width = 1))
      ) |>
        plotly::layout(
          title = "Доля типов атак среди алертов",
          showlegend = TRUE,
          legend = list(orientation = "v", x = 1.02, y = 0.5)
        )
    })

    output$topip <- plotly::renderPlotly({
      a <- filtered_alerts()
      shiny::req(nrow(a) > 0)
      g <- a[, .(
        alerts = .N,
        max_score = max(anomaly_score, na.rm = TRUE),
        top_type = attack_type[which.max(anomaly_score)]
      ), by = src_ip][order(-alerts)][1:min(.N, 20)]
      g[, type_label := vapply(top_type, function(tp) {
        get_attack_meta(tp)$label
      }, character(1))]
      g[, hover := paste0(
        src_ip, "\nалертов: ", alerts,
        "\nmax score: ", round(max_score, 4),
        "\nдомин. тип: ", type_label
      )]

      plotly::plot_ly(
        g, x = ~alerts, y = ~reorder(src_ip, alerts), type = "bar",
        orientation = "h",
        marker = list(color = .attack_palette(g$top_type)),
        text = ~hover, hoverinfo = "text"
      ) |>
        plotly::layout(
          title = "Топ источников по числу алертов",
          xaxis = list(title = "алертов"),
          yaxis = list(title = "")
        )
    })

    output$alerts_tbl <- DT::renderDT({
      a <- filtered_alerts()
      shiny::req(nrow(a) > 0)
      cols <- intersect(c("ts", "src_ip", "src_port", "dst_ip", "dst_port",
                          "proto", "attack_type", "attack_score", "anomaly_score",
                          "duration", "orig_bytes", "resp_bytes",
                          "conn_count_5min", "dest_port_distinct", "unique_dst_ip"),
                        names(a))
      DT::datatable(a[, cols, with = FALSE],
                    options = list(pageLength = 25, order = list(list(0, "desc"))),
                    rownames = FALSE,
                    selection = "single") |>
        DT::formatRound("anomaly_score", 4)
    })

    shiny::observeEvent(input$alerts_tbl_rows_selected, {
      sel <- input$alerts_tbl_rows_selected
      a <- filtered_alerts()
      if (length(sel) == 1L && nrow(a) >= sel) {
        rv$selected_alert_id <- a$alert_id[sel]
      }
    })
  }

  shiny::shinyApp(ui, server)
}

#' Запуск Shiny-дашборда
#'
#' @param port Порт.
#' @param host Хост (`0.0.0.0` для Docker).
#' @param ... Доп. аргументы для [shiny::runApp()].
#' @export
run_dashboard <- function(port = 4321L, host = "0.0.0.0", ...) {
  .check_dashboard_deps()
  options(shiny.maxRequestSize = 500 * 1024^2)
  shiny::runApp(ids_dashboard_app(), port = port, host = host, ...)
}
