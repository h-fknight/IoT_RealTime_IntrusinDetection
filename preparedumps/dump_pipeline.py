import os
import pandas as pd
# from sklearn.externals import joblib
import joblib
from sklearn.model_selection import train_test_split
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from preprocessing.data_preprocessor import AttributesRemover, CustomDataCleaner
from preprocessing import constants

CIC_IOT_Dataset2022_PATH = r".\\CIC_IOT_Dataset2022\normal_eq_attack.csv"
CSVFILENAME = "normal_eq_attack.csv"

columns = constants.COLUMNS


# Load the dataset
def load_ciot_data(cic2022_path=CIC_IOT_Dataset2022_PATH):
    return pd.read_csv(cic2022_path, low_memory=False)


def dump():
    dataset = load_ciot_data()

    #  Train Test Split
    train_set, test_set = train_test_split(dataset, test_size=0.5, random_state=123)

    # Prepare IDS Dataset
    # Removing columns
    dataclean_pipeline = Pipeline([
        ('attribs_remover', AttributesRemover()),
        ('data_cleaner', CustomDataCleaner()),
    ])

    dataprep_pipeline = Pipeline([
        ('standard_scaler', StandardScaler()),
    ])

    dataclean_pipeline.fit(train_set)
    dataprep_pipeline.fit(dataclean_pipeline.transform(train_set))
    joblib.dump(dataclean_pipeline, r'.\\preprocessing\joblib_dumps\dataclean_pipeline.joblib')
    joblib.dump(dataprep_pipeline, r'.\\preprocessing\joblib_dumps\dataprep_pipeline.joblib')


def createDumps():
    dump()
    return True


if __name__ == "__main__":
    createDumps()