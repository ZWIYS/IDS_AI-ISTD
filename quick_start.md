## Быстрый старт

1. Перед стартом:
  Убедиться в наличии Zeek в path вашей системы!
  Первый запуск без PCAP упадёт на стадии data — нужен хотя бы один .pcap в 
  ```R
  R Проект/data/pcap/
  ```
2. Установить пакет с github
  ```R
  install.packages("remotes")
  ```
  ```R
  remotes::install_github("ZWIYS/IDS_AI-ISTD")
  ```
3. Подключить пакет в R и указать путь
  ```R
  library(idsAiIstd)
  ```
  ```R
  init_ids_config("/Путь к R Проекту")
  ```
4. Добавление первого .pcap и запуск пайплайна
  Положить .pcap файл в /Проект R/data/pcap/
  ```R
  run_ids_pipeline()
  ```
5. Подключение дашборда
  ```R
  run_dashboard(port = 4321)
  ```
  или любой удобный вам порт

6*. Запуск docker контейнера
```
docker run --rm -it -p 4321:4321 \
  -v "$(pwd)/data:/app/data" \
  -v "$(pwd)/models:/app/models" \
  -v "$(pwd)/alerts:/app/alerts" \
  ghcr.io/zwiys/ids_ai-istd:<АКТУАЛЬНЫЙ ТЕГ> \
  bash -c "bash scripts/download_sample_pcaps.sh && Rscript run_pipeline.R && Rscript -e \"shiny::runApp('R/05_dashboard.R', port=4321, host='0.0.0.0')\""
```

