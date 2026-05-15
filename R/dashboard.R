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
load_alerts <- function() {
  if (!file.exists(PATHS$alerts_file) || file.info(PATHS$alerts_file)$size == 0) {
    return(data.table::data.table())
  }
  lines <- readLines(PATHS$alerts_file, warn = FALSE)
  lines <- lines[nzchar(lines)]
  if (!length(lines)) return(data.table::data.table())
  data.table::rbindlist(lapply(lines, jsonlite::fromJSON), fill = TRUE)
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
        shiny::verbatimTextOutput("pipeline_log"),
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
      bslib::nav_panel("Распределение score", plotly::plotlyOutput("hist", height = "360px")),
      bslib::nav_panel("Атаки во времени",     plotly::plotlyOutput("ts",   height = "360px")),
      bslib::nav_panel("Топ src_ip",           plotly::plotlyOutput("topip", height = "360px"))
    ),
    bslib::card(bslib::card_header("Алерты"), DT::DTOutput("alerts_tbl"))
  )

  server <- function(input, output, session) {
    rv <- shiny::reactiveValues(
      scored = load_scored(),
      alerts = load_alerts(),
      pipeline_log = ""
    )
    pipeline_busy <- shiny::reactiveVal(FALSE)

    refresh_dashboard <- function() {
      rv$scored <- load_scored()
      rv$alerts <- load_alerts()
      types <- sort(unique(rv$alerts$attack_type))
      shiny::updateSelectInput(session, "attack_filter", choices = types, selected = types)
    }

    shiny::observeEvent(input$refresh, refresh_dashboard(),
                        ignoreNULL = FALSE, ignoreInit = FALSE)

    output$pcap_queue <- shiny::renderText({
      files <- list_pcaps()
      if (!length(files)) return("Очередь пуста — загрузите PCAP")
      paste0(length(files), " файл(ов):\n", paste0(" • ", basename(files), collapse = "\n"))
    })

    output$pipeline_log <- shiny::renderText({
      if (!nzchar(rv$pipeline_log %||% "")) "Лог анализа появится здесь"
      else rv$pipeline_log
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
      rv$pipeline_log <- "Запуск…\n"
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
      rv$pipeline_log <- paste(c(log_lines,
        if (inherits(result, "error")) paste("ERROR:", result) else "Готово."),
        collapse = "\n")
      pipeline_busy(FALSE)
      shiny::updateActionButton(session, "run_pipeline", label = "Запустить анализ")

      if (inherits(result, "error")) {
        shiny::showNotification(paste("Ошибка:", result), type = "error", duration = NULL)
      } else {
        shiny::showNotification("Анализ завершён", type = "message")
        refresh_dashboard()
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
      a
    })

    output$n_sessions <- shiny::renderText(format(nrow(rv$scored), big.mark = " "))
    output$n_anom <- shiny::renderText(format(sum(rv$scored$is_anomaly %||% FALSE, na.rm = TRUE),
                                             big.mark = " "))
    output$n_alerts <- shiny::renderText(format(nrow(filtered_alerts()), big.mark = " "))
    output$n_src <- shiny::renderText({
      a <- filtered_alerts()
      if (!nrow(a)) "0" else format(data.table::uniqueN(a$src_ip), big.mark = " ")
    })

    output$hist <- plotly::renderPlotly({
      shiny::req(nrow(rv$scored) > 0)
      plotly::plot_ly(rv$scored, x = ~anomaly_score, type = "histogram", nbinsx = 60) |>
        plotly::layout(title = "Распределение anomaly_score",
                       xaxis = list(title = "score"), yaxis = list(title = "сессий"))
    })

    output$ts <- plotly::renderPlotly({
      a <- filtered_alerts()
      shiny::req(nrow(a) > 0)
      a[, t := as.POSIXct(safe_num(ts), origin = "1970-01-01", tz = "UTC")]
      a[, bucket := as.POSIXct(floor(as.numeric(t) / 60) * 60,
                               origin = "1970-01-01", tz = "UTC")]
      g <- a[, .N, by = .(bucket, attack_type)]
      plotly::plot_ly(g, x = ~bucket, y = ~N, color = ~attack_type, type = "bar") |>
        plotly::layout(barmode = "stack", xaxis = list(title = "время"),
                       yaxis = list(title = "алертов/мин"))
    })

    output$topip <- plotly::renderPlotly({
      a <- filtered_alerts()
      shiny::req(nrow(a) > 0)
      g <- a[, .N, by = src_ip][order(-N)][1:min(.N, 20)]
      plotly::plot_ly(g, x = ~N, y = ~reorder(src_ip, N), type = "bar", orientation = "h") |>
        plotly::layout(yaxis = list(title = ""), xaxis = list(title = "алертов"))
    })

    output$alerts_tbl <- DT::renderDT({
      a <- filtered_alerts()
      shiny::req(nrow(a) > 0)
      cols <- intersect(c("ts", "src_ip", "src_port", "dst_ip", "dst_port",
                          "proto", "attack_type", "attack_score", "anomaly_score",
                          "duration", "orig_bytes", "resp_bytes",
                          "conn_count_5min", "dest_port_distinct"),
                        names(a))
      DT::datatable(a[, cols, with = FALSE],
                    options = list(pageLength = 25, order = list(list(0, "desc"))),
                    rownames = FALSE) |>
        DT::formatRound("anomaly_score", 4)
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
