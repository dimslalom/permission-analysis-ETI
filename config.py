import os

# Kaggle API Configuration
KAGGLE_USERNAME = "dimasgistha"
KAGGLE_KEY = "f3e04557558b4941cb767f4ca44ce368"

# Dataset paths
PLAYSTORE_DATASET = "lava18/google-play-store-apps"
MALWARE_DATASET = "dannyrevaldo/android-malware-detection-dataset"

# Output directories
OUTPUT_DIR = "output"
REPORTS_DIR = os.path.join(OUTPUT_DIR, "reports")
VISUALIZATIONS_DIR = os.path.join(OUTPUT_DIR, "visualizations")

# Risk scoring weights
PERMISSION_WEIGHT = 0.4
SIZE_ANOMALY_WEIGHT = 0.2
REVIEW_PATTERN_WEIGHT = 0.2
CATEGORY_ANOMALY_WEIGHT = 0.2

# Risk thresholds
HIGH_RISK_THRESHOLD = 75

# Visualization settings
DPI = 300
PLOT_STYLE = "seaborn-v0_8"  # Changed from "seaborn" to "seaborn-v0_8"