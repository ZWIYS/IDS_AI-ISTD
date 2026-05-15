# =============================================================================
# 05_dashboard.R — БЛОК 6: Визуализация (Shiny dashboard)
# =============================================================================
# Запуск:
#   Rscript -e 'shiny::runApp("R/05_dashboard.R", port=4321, host="0.0.0.0")'
# =============================================================================

local({
  here <- tryCatch(dirname(sys.frame(1)$ofile), error = function(e) getwd())
  source(file.path(here, "00_config.R"), chdir = TRUE)
  source(file.path(here, "utils.R"),     chdir = TRUE)
})
source(file.path(.find_this_dir(), "pcap_upload.R"),     chdir = TRUE)
source(file.path(.find_this_dir(), "pipeline_runner.R"), chdir = TRUE)
ensure_packages(c(REQUIRED_PKGS, OPTIONAL_PKGS))

options(shiny.maxRequestSize = 500 * 1024^2)  # до 500 MB на файл

library(shiny); library(DT); library(plotly); library(bslib)

load_scored <- function() {
  if (!file.exists(PATHS$scored)) return(data.table::data.table())
  data.table::as.data.table(arrow::read_parquet(PATHS$scored))
}
load_alerts <- function() {
  if (!file.exists(PATHS$alerts_file) || file.info(PATHS$alerts_file)$size == 0)
    return(data.table::data.table())
  lines <- readLines(PATHS$alerts_file, warn = FALSE)
  lines <- lines[nzchar(lines)]
  if (!length(lines)) return(data.table::data.table())
  data.table::rbindlist(lapply(lines, jsonlite::fromJSON), fill = TRUE)
}

ui <- page_sidebar(
  title = "IoT IDS — Dashboard",
  theme = bs_theme(bootswatch = "flatly"),
  sidebar = sidebar(
    width = 380,
    card(
      card_header("Загрузка PCAP"),
      fileInput(
        "pcap_upload", NULL,
        multiple = TRUE, buttonLabel = "Выбрать…", placeholder = "не выбрано",
        accept = c(".pcap", ".pcapng", ".gz", ".PCAP", ".PCAPNG")
      ),
      checkboxInput("replace_pcaps", "Заменить ранее загруженные", TRUE),
      actionButton("run_pipeline", "Запустить анализ",
                   class = "btn-primary", icon = icon("play")),
      tags$small(class = "text-muted",
                 "Форматы: .pcap, .pcapng, .pcap.gz. Zeek обработает все файлы в очереди."),
      verbatimTextOutput("pipeline_log"),
      tags$hr(),
      textOutput("pcap_queue")
    ),
    actionButton("refresh", "Обновить дашборд", icon = icon("rotate")),
    selectInput("attack_filter", "Тип атаки:", choices = NULL, multiple = TRUE),
    sliderInput("score_min", "Min anomaly score:",
                min = 0, max = 1, value = 0, step = 0.01)
  ),
  layout_columns(
    value_box(title = "Сессий",       value = textOutput("n_sessions"), theme = "primary"),
    value_box(title = "Аномалий",     value = textOutput("n_anom"),     theme = "warning"),
    value_box(title = "Алертов",      value = textOutput("n_alerts"),   theme = "danger"),
    value_box(title = "Уник. src_ip", value = textOutput("n_src"),      theme = "info")
  ),
  navset_card_tab(
    nav_panel("Распределение score", plotlyOutput("hist", height = "360px")),
    nav_panel("Атаки во времени",     plotlyOutput("ts",   height = "360px")),
    nav_panel("Топ src_ip",           plotlyOutput("topip", height = "360px"))
  ),
  card(card_header("Алерты"), DTOutput("alerts_tbl"))
)

server <- function(input, output, session) {
  rv <- reactiveValues(
    scored = load_scored(),
    alerts = load_alerts(),
    pipeline_log = ""
  )
  pipeline_busy <- reactiveVal(FALSE)

  refresh_dashboard <- function() {
    rv$scored <- load_scored()
    rv$alerts <- load_alerts()
    types <- sort(unique(rv$alerts$attack_type))
    updateSelectInput(session, "attack_filter", choices = types, selected = types)
  }

  observeEvent(input$refresh, refresh_dashboard(),
               ignoreNULL = FALSE, ignoreInit = FALSE)

  output$pcap_queue <- renderText({
    files <- list_pcaps()
    if (!length(files)) return("Очередь пуста — загрузите PCAP")
    paste0(length(files), " файл(ов):\n", paste0(" • ", basename(files), collapse = "\n"))
  })

  output$pipeline_log <- renderText({
    if (!nzchar(rv$pipeline_log %||% "")) "Лог анализа появится здесь"
    else rv$pipeline_log
  })

  observeEvent(input$run_pipeline, {
    if (pipeline_busy()) {
      showNotification("Анализ уже выполняется", type = "warning")
      return()
    }
    if (is.null(input$pcap_upload) || !nrow(input$pcap_upload)) {
      existing <- list_pcaps()
      if (!length(existing)) {
        showNotification("Сначала загрузите PCAP", type = "error")
        return()
      }
    }

    pipeline_busy(TRUE)
    rv$pipeline_log <- "Запуск…\n"
    updateActionButton(session, "run_pipeline", label = "Выполняется…")

    withProgress(message = "Анализ PCAP", value = 0, {
      log_file <- tempfile()
      result <- tryCatch({
        if (!is.null(input$pcap_upload) && nrow(input$pcap_upload)) {
          incProgress(0.1, detail = "Сохранение PCAP")
          save_uploaded_pcaps(input$pcap_upload, replace = isTRUE(input$replace_pcaps))
        }
        incProgress(0.2, detail = "Zeek + ML pipeline")
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
    updateActionButton(session, "run_pipeline", label = "Запустить анализ")

    if (inherits(result, "error")) {
      showNotification(paste("Ошибка:", result), type = "error", duration = NULL)
    } else {
      showNotification("Анализ завершён", type = "message")
      refresh_dashboard()
    }
  })

  filtered_alerts <- reactive({
    a <- rv$alerts
    if (!nrow(a)) return(a)
    if (length(input$attack_filter))
      a <- a[attack_type %in% input$attack_filter]
    if (!is.null(input$score_min))
      a <- a[anomaly_score >= input$score_min]
    a
  })

  output$n_sessions <- renderText(format(nrow(rv$scored), big.mark = " "))
  output$n_anom     <- renderText(format(sum(rv$scored$is_anomaly %||% FALSE, na.rm = TRUE),
                                         big.mark = " "))
  output$n_alerts   <- renderText(format(nrow(filtered_alerts()), big.mark = " "))
  output$n_src      <- renderText({
    a <- filtered_alerts()
    if (!nrow(a)) "0" else format(data.table::uniqueN(a$src_ip), big.mark = " ")
  })

  output$hist <- renderPlotly({
    req(nrow(rv$scored) > 0)
    plot_ly(rv$scored, x = ~anomaly_score, type = "histogram", nbinsx = 60) |>
      layout(title = "Распределение anomaly_score",
             xaxis = list(title = "score"), yaxis = list(title = "сессий"))
  })

  output$ts <- renderPlotly({
    a <- filtered_alerts(); req(nrow(a) > 0)
    a[, t := as.POSIXct(safe_num(ts), origin = "1970-01-01", tz = "UTC")]
    a[, bucket := as.POSIXct(floor(as.numeric(t) / 60) * 60,
                             origin = "1970-01-01", tz = "UTC")]
    g <- a[, .N, by = .(bucket, attack_type)]
    plot_ly(g, x = ~bucket, y = ~N, color = ~attack_type, type = "bar") |>
      layout(barmode = "stack", xaxis = list(title = "время"),
             yaxis = list(title = "алертов/мин"))
  })

  output$topip <- renderPlotly({
    a <- filtered_alerts(); req(nrow(a) > 0)
    g <- a[, .N, by = src_ip][order(-N)][1:min(.N, 20)]
    plot_ly(g, x = ~N, y = ~reorder(src_ip, N), type = "bar", orientation = "h") |>
      layout(yaxis = list(title = ""), xaxis = list(title = "алертов"))
  })

  output$alerts_tbl <- renderDT({
    a <- filtered_alerts()
    req(nrow(a) > 0)
    cols <- intersect(c("ts", "src_ip", "src_port", "dst_ip", "dst_port",
                        "proto", "attack_type", "attack_score", "anomaly_score",
                        "duration", "orig_bytes", "resp_bytes",
                        "conn_count_5min", "dest_port_distinct"),
                      names(a))
    datatable(a[, cols, with = FALSE],
              options = list(pageLength = 25, order = list(list(0, "desc"))),
              rownames = FALSE) |>
      formatRound("anomaly_score", 4)
  })
}

shinyApp(ui, server)
