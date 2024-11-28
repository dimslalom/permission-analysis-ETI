import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from config import *

class RiskAnalyzer:
    def __init__(self, malware_df):
        self.malware_df = malware_df
        self.permission_risk_scores = self._calculate_permission_risk_scores()
        
    def _calculate_permission_risk_scores(self):
        # Calculate risk score for each permission
        permission_scores = {}
        
        # Count occurrences in malware and benign apps
        malware_apps = self.malware_df[self.malware_df['is_malware'] == 'Malware']
        benign_apps = self.malware_df[self.malware_df['is_malware'] == 'Benign']
        
        all_permissions = set()
        for perms in self.malware_df['permissions']:
            all_permissions.update(perms)
            
        for permission in all_permissions:
            malware_count = sum(1 for perms in malware_apps['permissions'] if permission in perms)
            benign_count = sum(1 for perms in benign_apps['permissions'] if permission in perms)
            
            # Calculate risk score using relative frequency
            malware_freq = malware_count / len(malware_apps) if len(malware_apps) > 0 else 0
            benign_freq = benign_count / len(benign_apps) if len(benign_apps) > 0 else 0
            
            # Risk score is higher when permission is more common in malware than benign apps
            risk_score = (malware_freq / (benign_freq + 0.01)) * 100
            permission_scores[permission] = min(risk_score, 100)
            
        return permission_scores

    def calculate_permission_risk(self, permissions):
        if not permissions:
            return 0
            
        # Calculate average risk score of all permissions
        risk_scores = [self.permission_risk_scores.get(p, 0) for p in permissions]
        return sum(risk_scores) / len(permissions) if risk_scores else 0

    def calculate_size_anomaly(self, size, category_sizes):
        if size is None or category_sizes.empty:
            return 0
        z_score = (size - np.mean(category_sizes)) / np.std(category_sizes)
        return min(abs(z_score) * 20, 100)  # Normalize to 0-100

    def calculate_risk_score(self, app_data):
        permission_score = self.calculate_permission_risk(app_data['permissions'])
        size_score = self.calculate_size_anomaly(app_data['size'], app_data['category_sizes'])
        
        final_score = (
            permission_score * PERMISSION_WEIGHT +
            size_score * SIZE_ANOMALY_WEIGHT
        )
        
        return min(final_score, 100)