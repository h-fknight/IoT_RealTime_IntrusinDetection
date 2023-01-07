import pandas as pd
import numpy as np
import glob
from preprocessing import constants

REMOVER_ATTRIBUTES = ["id", "expiration_id", "src_ip", "src_mac", "src_oui",
                      "src_port", "dst_ip", "dst_mac", "dst_oui",
                      "dst_port", "protocol", "ip_version", "vlan_id", "tunnel_id",
                      "application_name", "application_category_name",
                      "application_is_guessed", "application_confidence",
                      "requested_server_name", "client_fingerprint",
                      "server_fingerprint", "user_agent", "content_type"]


def data_prepare():
    full_name = glob.glob(pathname='./CIC_IOT_Dataset2022/'+'*.csv')
    whole_df = pd.DataFrame(columns=constants.COLUMNS)
    for file in full_name:
        df = pd.read_csv(file, low_memory=False)
        print(f"{file}:{df.shape}")
        if whole_df.empty:
            whole_df = df.copy(deep=True)
            print(f"First file:{whole_df.shape}")
        else:
            whole_df = pd.concat([whole_df,df], ignore_index=True)
            print(f"concat ok:{whole_df.shape}")
    whole_df.to_csv("./CIC_IOT_Dataset2022/normal_eq_attack.csv", index=None)


def test_data_clean():
    df = pd.read_csv("./capture/temp_00001_20230104113702.pcap.csv", low_memory=False)
    X = df.drop(columns=REMOVER_ATTRIBUTES)
    print(X.dtypes)
    # Check nan, +-inf values
    print(X[~X.isin([np.nan, np.inf, -np.inf]).any(1)].equals(X))


if __name__ == '__main__':
    data_prepare()