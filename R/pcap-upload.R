# =============================================================================
# pcap-upload.R — загрузка пользовательских PCAP (Shiny)
# =============================================================================

#' @keywords internal
PCAP_NAME_RE <- "\\.(pcap|pcapng)(\\.gz)?$"

#' Безопасное имя PCAP-файла
#' @param name Исходное имя.
#' @export
safe_pcap_filename <- function(name) {
  name <- basename(name %||% "")
  name <- gsub("[^A-Za-z0-9._-]", "_", name)
  if (!nzchar(name)) return("upload.pcap")
  if (!grepl(PCAP_NAME_RE, name, ignore.case = TRUE)) {
    name <- paste0(name, ".pcap")
  }
  name
}

#' Список PCAP в каталоге загрузок
#' @param dir Каталог.
#' @export
list_pcaps <- function(dir = PATHS$pcap_upload_dir) {
  dir <- normalizePath(dir, mustWork = FALSE)
  if (!dir.exists(dir)) return(character())
  sort(list.files(dir, PCAP_NAME_RE, full.names = TRUE, ignore.case = TRUE))
}

#' Удалить PCAP из каталога загрузок
#' @param dir Каталог.
#' @return Число удалённых файлов (невидимо).
#' @export
clear_pcaps <- function(dir = PATHS$pcap_upload_dir) {
  dir.create(dir, recursive = TRUE, showWarnings = FALSE)
  old <- list_pcaps(dir)
  if (length(old)) unlink(old)
  invisible(length(old))
}

#' Сохранить загруженные PCAP (Shiny fileInput)
#'
#' @param files Объект `data.frame` из `fileInput`.
#' @param replace Очистить каталог перед сохранением.
#' @param dest_dir Каталог назначения.
#' @return Пути сохранённых файлов (невидимо).
#' @export
save_uploaded_pcaps <- function(files, replace = TRUE, dest_dir = PATHS$pcap_upload_dir) {
  if (is.null(files) || !nrow(files)) stop("Файлы не выбраны")
  dir.create(dest_dir, recursive = TRUE, showWarnings = FALSE)
  if (replace) clear_pcaps(dest_dir)

  saved <- character()
  for (i in seq_len(nrow(files))) {
    src <- files$datapath[i]
    if (!file.exists(src)) next
    nm  <- safe_pcap_filename(files$name[i])
    if (!grepl(PCAP_NAME_RE, nm, ignore.case = TRUE)) {
      stop("Неподдерживаемый формат: ", files$name[i],
           " (нужен .pcap, .pcapng или .pcap.gz)")
    }
    dest <- file.path(dest_dir, nm)
    if (file.exists(dest)) {
      dest <- file.path(dest_dir,
                        sprintf("%s_%d", tools::file_path_sans_ext(nm),
                                as.integer(Sys.time())))
    }
    if (!grepl(PCAP_NAME_RE, basename(dest), ignore.case = TRUE)) {
      dest <- paste0(dest, ".pcap")
    }
    if (!file.copy(src, dest, overwrite = TRUE)) {
      stop("Не удалось сохранить: ", nm)
    }
    saved <- c(saved, dest)
  }
  if (!length(saved)) stop("Не удалось сохранить ни одного файла")
  log_info("PCAP saved: %d file(s) -> %s", length(saved), dest_dir)
  invisible(saved)
}
