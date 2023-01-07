# from sklearn.externals import joblib
import joblib
from preprocessing.data_preprocessor import IDSPipelineLoader, AttributesRemover

# PIPELINE_FILEPATH = "preprocessing/joblib_dumps/ids_pipeline.joblib"
DATACLEAN_PIPELINE_FILEPATH = "./preprocessing/joblib_dumps/dataclean_pipeline.joblib"
DATAPREP_PIPELINE_FILEPATH = "./preprocessing/joblib_dumps/dataprep_pipeline.joblib"
MODEL_FILEPATH = "./ml_models/lightgbm_binary_model.joblib"


class MLProcessor(object):
    def __init__(self, model_file=MODEL_FILEPATH):
        # Load ml model
        self.model = joblib.load(model_file)

        # Load the ids pipeline
        dataclean_PipelineLoader = IDSPipelineLoader(DATACLEAN_PIPELINE_FILEPATH)
        dataprep_PipelineLoader = IDSPipelineLoader(DATAPREP_PIPELINE_FILEPATH)

        self.dataclean_pipeline = dataclean_PipelineLoader.getPipeline()
        self.dataprep_pipeline = dataprep_PipelineLoader.getPipeline()

    def predict(self, data):
        """Execute the prediction task"""
        clean_data = self.dataclean_pipeline.transform(data)
        prep_data = self.dataprep_pipeline.transform(clean_data)
        return self.model.predict(prep_data)
