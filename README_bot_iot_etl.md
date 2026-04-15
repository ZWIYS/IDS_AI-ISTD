# BoT-IoT ETL — Модуль обработки PCAP для IoT IDS

## Назначение

ETL-пайплайн на R для обработки PCAP-дампов датасета  
**BoT-IoT (UNSW Canberra Cyber)** с целью подготовки признаковых таблиц  
для систем обнаружения вторжений (IDS) в сетях IoT.

Датасет включает более **72 млн записей** (69.3 GB PCAP, 16.7 GB CSV)  
с атаками: DDoS, DoS, Reconnaissance, Keylogging, Data Exfiltration.

---

## Архитектура пайплайна

```
[PCAP / CSV]
     │
     ▼ EXTRACT
  tshark → сырые пакеты (data.table)
     │
     ▼ TRANSFORM
  стандартизация колонок
  приведение типов
  5-кортеж flow_id
  агрегация пакетов → flow (43+ признака)
     │
     ▼ LABEL
  разметка по именам файлов / колонке category
  бинарная метка is_attack
     │
     ▼ CLEAN
  удаление невалидных строк
  импутация медианой
  удаление константных столбцов
     │
     ▼ NORMALIZE
  min-max / z-score
  сохранение scaler.rds для инференса
     │
     ▼ LOAD
  train / val / test (Parquet + CSV.gz)
  etl_report.csv
```

---

## Признаки (43 flow-признака)

### Идентификаторы (не используются в ML)
| Поле | Описание |
|------|----------|
| `session_id` | Уникальный ID потока |
| `src_ip`, `dst_ip` | IP-адреса |
| `src_port`, `dst_port` | Порты |
| `proto_name` | Протокол (TCP/UDP/ICMP) |

### Временны́е признаки
| Поле | Описание |
|------|----------|
| `duration` | Длительность потока (сек) |
| `duration_log` | log(1 + duration) |
| `mean_iat` | Среднее межпакетное время |
| `std_iat`, `min_iat`, `max_iat` | Статистика IAT |
| `iat_cv` | Коэффициент вариации IAT |

### Объём трафика
| Поле | Описание |
|------|----------|
| `pkt_count` | Количество пакетов |
| `byte_count` | Суммарный объём (байт) |
| `mean_pkt_len`, `min_pkt_len`, `max_pkt_len`, `std_pkt_len` | Статистика длин пакетов |
| `pkt_rate`, `byte_rate` | Скорость (пакет/с, байт/с) |
| `pkt_per_sec_log`, `byte_per_sec_log` | log-скорости |
| `pkt_per_byte` | Отношение пакетов к байтам |

### TCP/IP признаки
| Поле | Описание |
|------|----------|
| `mean_ttl`, `min_ttl` | TTL |
| `mean_win_size` | Размер окна TCP |
| `mean_ack_rtt` | RTT подтверждений |
| `has_syn`, `has_fin`, `has_rst`, `has_psh`, `has_ack` | Флаги TCP |
| `tcp_flags_agg` | Агрегированные флаги (bitwise OR) |
| `tcp_flag_entropy` | Энтропия набора флагов |
| `is_bidirectional` | Двунаправленный поток |

### Порты и протоколы
| Поле | Описание |
|------|----------|
| `port_class_src`, `port_class_dst` | well_known / registered / dynamic |
| `is_iot_proto` | MQTT (1883/8883) / CoAP (5683/5684) |

### Индикаторы атак
| Поле | Описание |
|------|----------|
| `scan_indicator` | ≤3 пакета, длительность <1с |
| `flood_indicator` | >1000 пакетов/с |
| `exfil_indicator` | >1 MB за <60с |

### Прикладной уровень
| Поле | Описание |
|------|----------|
| `has_dns`, `has_http`, `has_mqtt` | Наличие протоколов L7 |
| `icmp_type_mode` | Наиболее частый тип ICMP |

---

## Установка зависимостей

### Системные (Ubuntu/Debian)
```bash
sudo apt-get install tshark
```

### R-пакеты
```r
install.packages(c(
  "data.table", "dplyr", "tidyr", "stringr",
  "lubridate", "arrow", "logger", "R.utils"
))
```

---

## Запуск

### Режим PCAP (сырые дампы)
```r
source("bot_iot_etl.R")

ETL_CONFIG$pcap_dir <- "path/to/pcap_files"
result <- run_etl(pcap_dir = "path/to/pcap_files")
```

### Режим CSV (готовые файлы BoT-IoT)
```r
source("bot_iot_etl.R")

result <- run_etl(pcap_dir = NULL, csv_dir = "path/to/UNSW_2018_IoT_Botnet_*.csv")
```

### Командная строка
```bash
Rscript bot_iot_etl.R /path/to/pcap /path/to/csv
```

---

## Выходные данные

```
data/processed/
├── train/
│   └── bot_iot_train.parquet   # 70% данных
│   └── bot_iot_train.csv.gz
├── val/
│   └── bot_iot_val.parquet     # 15% данных
│   └── bot_iot_val.csv.gz
├── test/
│   └── bot_iot_test.parquet    # 15% данных
│   └── bot_iot_test.csv.gz
├── scaler.rds                  # параметры нормализации
└── etl_report.csv              # сводка распределения меток
```

---

## Инференс (применение scaler к новым данным)

```r
source("bot_iot_etl.R")
new_data <- arrow::read_parquet("new_flows.parquet")
scaled   <- apply_scaler(new_data, "data/processed/scaler.rds")
```

---

## Ссылки

- Koroniotis et al. "Bot-iot dataset." *FGCS* 100 (2019): 779-796.  
- Датасет: https://research.unsw.edu.au/projects/bot-iot-dataset  
- NF-BoT-IoT-v2 (NetFlow-версия): https://staff.itee.uq.edu.au/marius/NIDS_datasets/
