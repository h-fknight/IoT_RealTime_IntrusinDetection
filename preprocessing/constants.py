from enum import Enum


# PredictLabel() is an enum for BENIGN or ANOMALY prediction output of
# ML models doing novelty detection.

# Useless
class PredictLabel(Enum):
    BENIGN = 1
    ANOMALY = -1


# Column names for NFStream generated datasets.


COLUMNS = ['id', 'expiration_id', 'src_ip', 'src_mac', 'src_oui', 'src_port',
           'dst_ip', 'dst_mac', 'dst_oui', 'dst_port', 'protocol', 'ip_version',
           'vlan_id', 'tunnel_id', 'bidirectional_first_seen_ms',
           'bidirectional_last_seen_ms', 'bidirectional_duration_ms',
           'bidirectional_packets', 'bidirectional_bytes', 'src2dst_first_seen_ms',
           'src2dst_last_seen_ms', 'src2dst_duration_ms', 'src2dst_packets',
           'src2dst_bytes', 'dst2src_first_seen_ms', 'dst2src_last_seen_ms',
           'dst2src_duration_ms', 'dst2src_packets', 'dst2src_bytes',
           'bidirectional_min_ps', 'bidirectional_mean_ps',
           'bidirectional_stddev_ps', 'bidirectional_max_ps', 'src2dst_min_ps',
           'src2dst_mean_ps', 'src2dst_stddev_ps', 'src2dst_max_ps',
           'dst2src_min_ps', 'dst2src_mean_ps', 'dst2src_stddev_ps',
           'dst2src_max_ps', 'bidirectional_min_piat_ms',
           'bidirectional_mean_piat_ms', 'bidirectional_stddev_piat_ms',
           'bidirectional_max_piat_ms', 'src2dst_min_piat_ms',
           'src2dst_mean_piat_ms', 'src2dst_stddev_piat_ms', 'src2dst_max_piat_ms',
           'dst2src_min_piat_ms', 'dst2src_mean_piat_ms', 'dst2src_stddev_piat_ms',
           'dst2src_max_piat_ms', 'bidirectional_syn_packets',
           'bidirectional_cwr_packets', 'bidirectional_ece_packets',
           'bidirectional_urg_packets', 'bidirectional_ack_packets',
           'bidirectional_psh_packets', 'bidirectional_rst_packets',
           'bidirectional_fin_packets', 'src2dst_syn_packets',
           'src2dst_cwr_packets', 'src2dst_ece_packets', 'src2dst_urg_packets',
           'src2dst_ack_packets', 'src2dst_psh_packets', 'src2dst_rst_packets',
           'src2dst_fin_packets', 'dst2src_syn_packets', 'dst2src_cwr_packets',
           'dst2src_ece_packets', 'dst2src_urg_packets', 'dst2src_ack_packets',
           'dst2src_psh_packets', 'dst2src_rst_packets', 'dst2src_fin_packets',
           'application_name', 'application_category_name',
           'application_is_guessed', 'application_confidence',
           'requested_server_name', 'client_fingerprint', 'server_fingerprint',
           'user_agent', 'content_type', "label", "cate"]

REMOVER_ATTRIBUTES = ["id", "expiration_id", "src_ip", "src_mac", "src_oui",
                      "src_port", "dst_ip", "dst_mac", "dst_oui",
                      "dst_port", "protocol", "ip_version", "vlan_id", "tunnel_id",
                      "application_name", "application_category_name",
                      "application_is_guessed", "application_confidence",
                      "requested_server_name", "client_fingerprint",
                      "server_fingerprint", "user_agent", "content_type", "label", "cate"]
