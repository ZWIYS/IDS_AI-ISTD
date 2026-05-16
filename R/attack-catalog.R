# =============================================================================
# attack-catalog.R — описания атак, правила и пояснения сработок
# =============================================================================

#' @keywords internal
.attack_catalog <- function() {
  list(
    ddos = list(
      label = "DDoS",
      description = paste(
        "Распределённая атака отказа в обслуживании: источник генерирует",
        "очень много соединений к ограниченному числу портов/узлов, перегружая",
        "цель или канал. Типичный признак — высокая частота коннектов при низком",
        "разнообразии портов назначения."
      ),
      rule = "conn_count_5min ≥ 500 и dest_port_distinct ≤ 5 (строго); адаптивно: conn_count_5min ≥ thr_conn и dest_port_distinct ≤ 3."
    ),
    port_scan = list(
      label = "Сканирование портов",
      description = paste(
        "Разведка сети: один хост обращается ко множеству портов на цели",
        "(или множеству целей), чтобы найти открытые сервисы перед эксплуатацией."
      ),
      rule = "conn_count_5min ≥ 100 и dest_port_distinct ≥ 50; адаптивно: conn_count_5min ≥ thr_conn/4 и dest_port_distinct ≥ max(3, thr_ports/2)."
    ),
    exfiltration = list(
      label = "Эксфильтрация",
      description = paste(
        "Подозрительная утечка данных: много исходящего трафика при почти",
        "отсутствии ответа — возможная передача данных наружу."
      ),
      rule = "conn_count_5min ≥ 300, orig_bytes > 100000, resp_bytes < 1000; адаптивно: orig_bytes > 50000, resp_bytes < 500, conn_count_5min ≥ 3."
    ),
    botnet = list(
      label = "Ботнет / C2",
      description = paste(
        "Поведение заражённого узла: много коротких сессий к разным",
        "хостам назначения — характерно для командных каналов и бот-сетей."
      ),
      rule = "conn_count_5min ≥ 200 и unique_dst_ip ≥ 20; адаптивно: unique_dst_ip ≥ max(2, thr_dst/2) и conn_count_5min ≥ 3."
    ),
    dos = list(
      label = "DoS",
      description = paste(
        "Атака отказа в обслуживании: массовые очень короткие соединения,",
        "направленные на истощение ресурсов сервиса."
      ),
      rule = "conn_count_5min ≥ 400 и duration < 0.1 с; адаптивно: duration < 0.5 и conn_count_5min ≥ max(3, thr_conn/4)."
    ),
    dns_anomaly = list(
      label = "Аномалия DNS",
      description = paste(
        "Подозрительные DNS-запросы: необычно длинные имена или высокая",
        "энтропия (случайные поддомены) — возможны туннелирование или DGA."
      ),
      rule = "query_entropy ≥ порога или query_length ≥ порога (см. DETECT_PARAMS$rules)."
    ),
    http_anomaly = list(
      label = "Аномалия HTTP",
      description = paste(
        "Подозрительный веб-трафик: слишком длинный URI или коды ответа ≥ 400",
        "(ошибки/сканирование уязвимостей)."
      ),
      rule = "uri_length ≥ порога или http_status_code ≥ 400."
    ),
    ssl_anomaly = list(
      label = "Аномалия TLS/SNI",
      description = paste(
        "Нетипичный TLS ClientHello: длинное или высокоэнтропийное SNI",
        "(обфускация, туннели, вредоносные домены)."
      ),
      rule = "ssl_sni_entropy ≥ порога и ssl_sni_length ≥ 8."
    ),
    traffic_spike = list(
      label = "Всплеск трафика",
      description = paste(
        "Резкий рост объёма данных относительно недавней истории —",
        "возможна аномальная активность или заливка канала."
      ),
      rule = "data_volume_change ≥ порога volume_pct (%)."
    ),
    proxy_tunnel = list(
      label = "Прокси / туннель",
      description = paste(
        "Сервисы IRC/SOCKS часто используются для проксирования и обхода",
        "фильтрации; сочетание с аномальным score указывает на туннель."
      ),
      rule = "service ∈ {irc, socks}."
    ),
    ml_anomaly = list(
      label = "ML-аномалия",
      description = paste(
        "Сессия отклоняется от нормы по модели Isolation Forest, но ни одно",
        "rule-based правило не назначило конкретный тип атаки. Требуется ручной",
        "разбор признаков."
      ),
      rule = "Нет срабатывания rule-based правил; классификация: fallback_type."
    )
  )
}

#' Метаданные типа атаки
#'
#' @param attack_type Код типа (`ddos`, `port_scan`, …).
#' @return Список с `label`, `description`, `rule`.
#' @keywords internal
get_attack_meta <- function(attack_type) {
  cat <- .attack_catalog()
  key <- attack_type %||% "ml_anomaly"
  if (!key %in% names(cat)) {
    return(list(
      label = as.character(key),
      description = "Тип атаки не описан в каталоге — проверьте признаки сессии вручную.",
      rule = "Правило не задокументировано для данного типа."
    ))
  }
  cat[[key]]
}

#' @keywords internal
.fmt_num <- function(x, digits = 2L) {
  if (is.null(x) || length(x) == 0L || is.na(x)) return("—")
  format(round(safe_num(x), digits), big.mark = " ", scientific = FALSE, trim = TRUE)
}

#' @keywords internal
.fmt_ts <- function(ts) {
  t <- as.POSIXct(safe_num(ts), origin = "1970-01-01", tz = "UTC")
  if (is.na(t)) "—" else format(t, "%Y-%m-%d %H:%M:%S UTC")
}

#' Пояснение сработки для одного алерта
#'
#' @param row Одна строка `data.table` / список с признаками алерта.
#' @param rules Пороги (`DETECT_PARAMS$rules`).
#' @return Список: `attack_label`, `description`, `rule_text`, `why`, `metrics`.
#' @keywords internal
explain_alert <- function(row, rules = DETECT_PARAMS$rules) {
  row <- as.list(row)
  atype <- row$attack_type %||% rules$fallback_type %||% "ml_anomaly"
  meta <- get_attack_meta(atype)

  conn  <- safe_num(row$conn_count_5min)
  ports <- safe_num(row$dest_port_distinct)
  dsts  <- safe_num(row$unique_dst_ip)
  dur   <- safe_num(row$duration)
  ob    <- safe_num(row$orig_bytes)
  rb    <- safe_num(row$resp_bytes)
  qe    <- safe_num(row$query_entropy)
  ql    <- safe_num(row$query_length)
  uri   <- safe_num(row$uri_length)
  http  <- safe_num(row$http_status_code)
  ssl_e <- safe_num(row$ssl_sni_entropy)
  ssl_l <- safe_num(row$ssl_sni_length)
  vol   <- safe_num(row$data_volume_change)
  svc   <- row$service %||% ""

  thr_conn  <- .adaptive_min(conn, 500)
  thr_ports <- .adaptive_min(ports, 50)
  thr_dst   <- .adaptive_min(dsts, 20)

  why <- character()
  matched_rule <- meta$rule

  if (atype == "ddos") {
    if (conn >= 500 && ports <= 5) {
      matched_rule <- "Правило (строгое): conn_count_5min ≥ 500 AND dest_port_distinct ≤ 5"
      why <- sprintf(
        "conn_count_5min = %s (≥ 500), dest_port_distinct = %s (≤ 5)",
        .fmt_num(conn, 0), .fmt_num(ports, 0)
      )
    } else {
      matched_rule <- sprintf(
        "Правило (адаптивное): conn_count_5min ≥ %s AND dest_port_distinct ≤ 3",
        .fmt_num(thr_conn, 0)
      )
      why <- sprintf(
        "conn_count_5min = %s, dest_port_distinct = %s (мало уникальных портов при высокой частоте)",
        .fmt_num(conn, 0), .fmt_num(ports, 0)
      )
    }
  } else if (atype == "port_scan") {
    matched_rule <- "Правило: высокая частота соединений + много разных портов назначения"
    why <- sprintf(
      "conn_count_5min = %s, dest_port_distinct = %s (пороги: ≥100/≥50 или адаптивные %s/%s)",
      .fmt_num(conn, 0), .fmt_num(ports, 0), .fmt_num(max(3, thr_conn %/% 4), 0),
      .fmt_num(max(3, thr_ports %/% 2), 0)
    )
  } else if (atype == "exfiltration") {
    matched_rule <- "Правило: много исходящих байт при малом ответе"
    why <- sprintf(
      "orig_bytes = %s, resp_bytes = %s, conn_count_5min = %s",
      .fmt_num(ob, 0), .fmt_num(rb, 0), .fmt_num(conn, 0)
    )
  } else if (atype == "botnet") {
    matched_rule <- "Правило: много уникальных dst_ip при активных соединениях"
    why <- sprintf(
      "unique_dst_ip = %s, conn_count_5min = %s (адаптивный порог dst: %s)",
      .fmt_num(dsts, 0), .fmt_num(conn, 0), .fmt_num(max(2, thr_dst %/% 2), 0)
    )
  } else if (atype == "dos") {
    matched_rule <- "Правило: короткие сессии при высокой частоте"
    why <- sprintf(
      "duration = %s с, conn_count_5min = %s",
      .fmt_num(dur, 3), .fmt_num(conn, 0)
    )
  } else if (atype == "dns_anomaly") {
    matched_rule <- sprintf(
      "Правило: query_entropy ≥ %s OR query_length ≥ %s",
      rules$query_entropy, rules$query_length
    )
    why <- sprintf(
      "query_entropy = %s, query_length = %s",
      .fmt_num(qe, 2), .fmt_num(ql, 0)
    )
  } else if (atype == "http_anomaly") {
    matched_rule <- sprintf(
      "Правило: uri_length ≥ %s OR http_status_code ≥ 400",
      rules$uri_length
    )
    why <- sprintf(
      "uri_length = %s, http_status_code = %s",
      .fmt_num(uri, 0), .fmt_num(http, 0)
    )
  } else if (atype == "ssl_anomaly") {
    matched_rule <- sprintf(
      "Правило: ssl_sni_entropy ≥ %s AND ssl_sni_length ≥ 8",
      rules$ssl_entropy
    )
    why <- sprintf(
      "ssl_sni_entropy = %s, ssl_sni_length = %s",
      .fmt_num(ssl_e, 2), .fmt_num(ssl_l, 0)
    )
  } else if (atype == "traffic_spike") {
    matched_rule <- sprintf("Правило: data_volume_change ≥ %s%%", rules$volume_pct)
    why <- sprintf("data_volume_change = %s%%", .fmt_num(vol, 1))
  } else if (atype == "proxy_tunnel") {
    matched_rule <- "Правило: service ∈ {irc, socks}"
    why <- sprintf("service = %s", if (nzchar(svc)) svc else "—")
  } else if (atype == "ml_anomaly") {
    matched_rule <- "Правило: fallback — только ML (Isolation Forest)"
    why <- sprintf(
      "anomaly_score = %s выше порога модели; rule-based условия не выполнены",
      .fmt_num(row$anomaly_score, 4)
    )
  }

  metrics <- list(
    `Время` = .fmt_ts(row$ts),
    `Источник` = paste0(row$src_ip %||% "—", ":", row$src_port %||% "—"),
    `Назначение` = paste0(row$dst_ip %||% "—", ":", row$dst_port %||% "—"),
    `Протокол` = as.character(row$proto %||% "—"),
    `Anomaly score` = .fmt_num(row$anomaly_score, 4),
    `Уверенность правила` = paste0("attack_score = ", .fmt_num(row$attack_score, 0)),
    `Соединений / 5 мин` = .fmt_num(conn, 0),
    `Уник. портов` = .fmt_num(ports, 0),
    `Уник. dst IP` = .fmt_num(dsts, 0),
    `Длительность` = paste0(.fmt_num(dur, 3), " с"),
    `orig / resp bytes` = paste0(.fmt_num(ob, 0), " / ", .fmt_num(rb, 0))
  )

  list(
    attack_label = meta$label,
    description = meta$description,
    rule_text = matched_rule,
    why = why,
    metrics = metrics
  )
}
