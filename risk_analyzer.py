import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from config import *

class RiskAnalyzer:
    def __init__(self):
        self.scaler = StandardScaler()
    
    def calculate_permission_risk(self, permissions):
        if not isinstance(permissions, list):
            permissions = []
        dangerous_permissions = [
            'READ_CONTACTS',
            'ACCESS_FINE_LOCATION',
            'RECORD_AUDIO',
            'CAMERA',
            'READ_SMS'
        ]
        
        permission_count = len(permissions)
        dangerous_count = sum(1 for p in permissions if p in dangerous_permissions)
        return (dangerous_count / max(permission_count, 1)) * 100

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