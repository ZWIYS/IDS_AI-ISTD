# Global variables for NSE (data.table, Shiny)
utils::globalVariables(c(
  ".", "i.", "N",
  "PROJECT_ROOT", "PATHS", "MODEL_PARAMS", "DETECT_PARAMS", "ZEEK_BIN",
  "FEATURE_DEFAULTS", "NUM_FEATURES", "CAT_FEATURES",
  "src_ip", "dst_ip", "dst_port", "ts", "bucket", "uid",
  "conn_count_5min", "dest_port_distinct", "unique_dst_ip",
  "duration", "orig_bytes", "resp_bytes", "missed_bytes",
  "orig_pkts", "resp_pkts", "total_bytes", "bytes_per_sec", "pkt_ratio",
  "history_length", "query_length", "query_entropy", "num_labels",
  "uri_length", "ua_length", "http_status_code", "ssl_sni_length", "ssl_sni_entropy",
  "bytes_5min", "data_volume_change", "prev_bytes",
  "attack_score", "attack_type", "anomaly_score", "is_anomaly",
  "attack_type", "service", "source_file", "proto"
))
