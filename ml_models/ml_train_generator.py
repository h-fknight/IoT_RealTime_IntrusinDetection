import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
from sklearn.svm import OneClassSVM
import lightgbm
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix, accuracy_score
from preprocessing import constants
from preprocessing.data_preprocessor import AttributesRemover, CustomDataCleaner, \
    MyLabelEncoder, AnomalyLabelEncoder, BenignLabelEncoder

# "./../" can be expressed as parent directory
local_dir = "./"
ciot_filename = r"..\CIC_IOT_Dataset2022\normal_eq_attack_label.csv.csv"


class DatasetProperties(object):
    def __init__(self, data_dir, filename):
        self.dir = data_dir
        self.filename = filename


class TrainTask(object):
    def __init__(self, datasetprop, localTrain):
        self.datasetprop = datasetprop
        self.localTrain = localTrain

    def create_train_test_df(self, dataframe, test_size=0.5):
        train_set, test_set = train_test_split(dataframe, test_size=test_size, random_state=123)
        return train_set, test_set

    def loadDatasets(self, data_dir, filename, localTrain=True):
        if localTrain:
            raw_dataset = pd.read_csv(os.path.join(data_dir, filename))
            return raw_dataset
        else:
            pass

    def train_and_evaluate(self):
        data_dir = self.datasetprop.dir
        filename = self.datasetprop.filename
        self.dataset = self.loadDatasets(data_dir, filename, self.localTrain)
        train_set, test_set = self.create_train_test_df(self.dataset)
        # train_set = self.dataset  # using te full dataset

        # Prepare IDS Dataset
        # In real detection there are no ['label', 'cate'], so if you want to execute this py in offline mode,
        # you should change the REMOVER_ATTRIBUTES in data_preprocessor
        dataclean_pipeline = Pipeline([
            ('attribs_remover', AttributesRemover()),
            ('data_cleaner', CustomDataCleaner()),
        ])

        prepdata_pipeline = Pipeline([
            ('standard_scaler', StandardScaler()),
        ])

        ids_label_pipeline = Pipeline([
            ('label_encoder', MyLabelEncoder()),
        ])

        # 1 Benign 0 Attack
        train_x = train_set.copy()
        train_x = dataclean_pipeline.fit_transform(train_x)
        train_y = train_set['label'].copy()

        # Firstly use train_set fit the prepdata_pipeline, ids_label_pipeline
        train_x_prepared = prepdata_pipeline.fit_transform(train_x)
        train_y_prepared = ids_label_pipeline.fit_transform(train_y)

        # Secondly use the fitted pipeline transform the test_set
        test_x = test_set.copy()
        test_x = dataclean_pipeline.transform(test_x)
        test_y = test_set["label"].copy()

        test_x_prepared = prepdata_pipeline.transform(test_x)
        test_y_prepared = ids_label_pipeline.transform(test_y)

        # Creating an object for model and fitting it on training data set
        estimator = lightgbm.LGBMClassifier()
        estimator.fit(train_x_prepared, train_y_prepared)

        # Predicting the Target variable
        pred = estimator.predict(test_x_prepared)

        # test ml performance
        acc = accuracy_score(y_true=test_y_prepared, y_pred=pred)
        f1 = f1_score(y_true=test_y_prepared, y_pred=pred)
        ps = precision_score(y_true=test_y_prepared, y_pred=pred)
        rs = recall_score(y_true=test_y_prepared, y_pred=pred)
        print(f"Accuracy:{acc}\tPrecision:{ps}\tRecall:{rs}\tF1:{f1:.2f}")

        # use to save estimator
        return estimator

    def save_model(self, model):
        # Save Monday dataset trained model
        model_filename = "lightgbm_binary_model.joblib"
        joblib.dump(model, model_filename)


if __name__ == "__main__":
    localTrain = True
    data_dir = ""
    if localTrain:
        print("LocalTrain == True")
        data_dir = local_dir
    else:
        pass

    task = TrainTask(DatasetProperties(data_dir, ciot_filename), localTrain=localTrain)
    model = task.train_and_evaluate()

    # Saved the model
    # task.save_model(model)
