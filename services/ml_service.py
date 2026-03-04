import xgboost as xgb
from utils.feature_extractor import extract_features

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

    def predict(self, url: str) -> float:
        features = extract_features(url)
        dmatrix = xgb.DMatrix([features], feature_names=self.feature_names)
        return float(self.model.predict(dmatrix)[0])

# Inisialisasi model
ml_engine = PhishingPredictor("models/phishing_model.json")