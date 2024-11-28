import kaggle
import pandas as pd
from tqdm import tqdm
import logging
from config import *

class DataLoader:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def fetch_datasets(self):
        try:
            kaggle.api.authenticate()
            kaggle.api.dataset_download_files(PLAYSTORE_DATASET, path=OUTPUT_DIR, unzip=True)
            kaggle.api.dataset_download_files(MALWARE_DATASET, path=OUTPUT_DIR, unzip=True)
        except Exception as e:
            self.logger.error(f"Failed to fetch datasets: {str(e)}")
            raise

    def load_and_clean_data(self):
        try:
            playstore_df = pd.read_csv(os.path.join(OUTPUT_DIR, "googleplaystore.csv"))
            malware_df = pd.read_csv(os.path.join(OUTPUT_DIR, "Android_Malware_Benign.csv"))
            
            # Log the column names for debugging
            self.logger.info(f"Malware dataset columns: {malware_df.columns.tolist()}")
            
            # Clean datasets
            playstore_df = self._clean_playstore_data(playstore_df)
            malware_df = self._clean_malware_data(malware_df)
            
            # Merge permissions into Play Store dataset
            playstore_df = self._merge_permissions(playstore_df, malware_df)
            
            return playstore_df, malware_df
            
        except Exception as e:
            self.logger.error(f"Failed to load and clean data: {str(e)}")
            raise
    
    def _clean_playstore_data(self, df):
        # Remove duplicates
        df = df.drop_duplicates()
        # Handle missing values
        df = df.dropna(subset=['App', 'Category'])
        
        # Convert Size to numeric, removing 'k' or 'M' and converting to MB
        df['Size'] = df['Size'].apply(self._convert_size_to_mb)
        
        return df
    
    def _convert_size_to_mb(self, size_str):
        try:
            if pd.isna(size_str) or size_str == 'Varies with device':
                return None
            
            size_str = size_str.upper()
            if 'K' in size_str:
                return float(size_str.replace('K', '')) / 1024
            elif 'M' in size_str:
                return float(size_str.replace('M', ''))
            else:
                return float(size_str)
        except:
            return None

    def _clean_malware_data(self, df):
        try:
            # Remove duplicates
            df = df.drop_duplicates()
            
            # All columns except 'Label' are permissions
            permission_columns = [col for col in df.columns if col != 'Label']
            
            # Convert the wide format (one permission per column) to a list of permissions per row
            df.loc[:, 'permissions'] = df[permission_columns].apply(
                lambda x: [col for col, val in x.items() if val == 1], 
                axis=1
            )
            
            # Create a simplified dataframe with just permissions and label
            result_df = pd.DataFrame({
                'app_name': df.index.astype(str),  # Ensure app_name is a string
                'permissions': df['permissions'],
                'is_malware': df['Label']
            })
            
            return result_df
            
        except Exception as e:
            self.logger.error(f"Error cleaning malware data: {str(e)}")
            self.logger.error(f"Available columns: {df.columns.tolist()}")
            raise

    def _merge_permissions(self, playstore_df, malware_df):
        try:
            # Ensure both columns are strings
            playstore_df['App'] = playstore_df['App'].astype(str)
            malware_df['app_name'] = malware_df['app_name'].astype(str)
            
            # Merge permissions into Play Store dataset based on app name
            merged_df = pd.merge(playstore_df, malware_df[['app_name', 'permissions']], left_on='App', right_on='app_name', how='left')
            merged_df.drop(columns=['app_name'], inplace=True)
            
            # Add Permission_Count column
            merged_df['Permission_Count'] = merged_df['permissions'].apply(lambda x: len(x) if isinstance(x, list) else 0)
            
            return merged_df
        except Exception as e:
            self.logger.error(f"Error merging permissions: {str(e)}")
            raise