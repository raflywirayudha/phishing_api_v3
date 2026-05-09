import xgboost as xgb
from ml.feature_extractor import extract_features

class PhishingPredictor:
    def __init__(self, model_path: str):
        self.model = xgb.Booster()
        self.model.load_model(model_path)
        self.feature_names = [
            "url_len", "dom_len", "is_ip", "tld_len", "subdom_cnt", "letter_cnt", 
            "digit_cnt", "special_cnt", "eq_cnt", "qm_cnt", "amp_cnt", "dot_cnt", 
            "dash_cnt", "under_cnt", "letter_ratio", "digit_ratio", "spec_ratio", 
            "is_https", "slash_cnt", "entropy", "path_len", "query_len"
        ]

    def predict(self, url: str):
        features = extract_features(url)
        feature_map = [
            {"Feature": name, "Value": val} 
            for name, val in zip(self.feature_names, features)
        ]
        dmatrix = xgb.DMatrix([features], feature_names=self.feature_names)
        prob = float(self.model.predict(dmatrix)[0])
        return {"probability": prob, "features": feature_map}

# Inisialisasi model
ml_engine = PhishingPredictor("ml/model.json")