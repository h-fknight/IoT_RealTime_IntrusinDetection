import numpy as np
import pandas
from sklearn.preprocessing import LabelEncoder
from sklearn.base import BaseEstimator, TransformerMixin

# from sklearn.externals import joblib
import joblib

REMOVER_ATTRIBUTES = ["id", "expiration_id", "src_ip", "src_mac", "src_oui",
                      "src_port", "dst_ip", "dst_mac", "dst_oui",
                      "dst_port", "protocol", "ip_version", "vlan_id", "tunnel_id",
                      "application_name", "application_category_name",
                      "application_is_guessed", "application_confidence",
                      "requested_server_name", "client_fingerprint",
                      "server_fingerprint", "user_agent", "content_type"]


# Data Preprocessing
class AttributesRemover(BaseEstimator, TransformerMixin):
    def __init__(self, columns=REMOVER_ATTRIBUTES):
        self.columns = columns

    def fit(self, X, y=None):
        return self  # nothing else to do

    def transform(self, X, y=None):
        # delete the whole column
        return X.drop(columns=self.columns, axis=1)


# CustomDataCleaner removes NaN,-Infinity, & +Infinity values from columns
# and also fixes the datatype of both columns.
class CustomDataCleaner(TransformerMixin):
    def __init__(self, *args, **kwargs):
        pass

    def fit(self, X, y=None):
        return self

    def transform(self, X, y=None):
        # Remove nan and inf values in df
        return X[~X.isin([np.nan, np.inf, -np.inf]).any(1)]


class MyLabelEncoder(TransformerMixin):
    def __init__(self, *args, **kwargs):
        self.encoder = LabelEncoder(*args, **kwargs)

    def fit(self, x, y=0):
        self.encoder.fit(x)
        return self

    def transform(self, x, y=0):
        return self.encoder.transform(x)


class AnomalyLabelEncoder(TransformerMixin):
    def __init__(self, *args, **kwargs):
        pass

    def fit(self, X, y=None):
        return self

    def transform(self, X, y=None):
        return ((X * 0) - 1)


class BenignLabelEncoder(TransformerMixin):
    def __init__(self, *args, **kwargs):
        pass

    def fit(self, X, y=None):
        return self

    def transform(self, X, y=None):
        return ((X * 0) + 1)


# IDSPipeline loads the saved pipeline from file.
class IDSPipelineLoader(object):
    def __init__(self, pipeline_filename):
        self.ids_pipeline = joblib.load(pipeline_filename)

    def getPipeline(self):
        return self.ids_pipeline