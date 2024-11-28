import shutil
import kaggle
import numpy as np
import pandas as pd
from tqdm import tqdm
import logging
import os
import zipfile
from config import *

class DataLoader:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def fetch_datasets(self):
        try:
            kaggle.api.authenticate()
            self._download_and_extract(PLAYSTORE_DATASET, OUTPUT_DIR)
            self._download_and_extract(MALWARE_DATASET, OUTPUT_DIR)
        except Exception as e:
            self.logger.error(f"Failed to fetch datasets: {str(e)}")
            raise

    def _download_and_extract(self, dataset, path):
        try:
            kaggle.api.dataset_download_files(dataset, path=path, unzip=False)
            zip_path = os.path.join(path, f"{dataset.split('/')[-1]}.zip")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for member in zip_ref.namelist():
                    filename = os.path.basename(member)
                    if not filename:
                        continue
                    source = zip_ref.open(member)
                    target = open(os.path.join(path, filename), "wb")
                    with source, target:
                        shutil.copyfileobj(source, target)
            os.remove(zip_path)
        except Exception as e:
            self.logger.error(f"Failed to download and extract dataset {dataset}: {str(e)}")
            raise

    def load_and_clean_data(self):
        try:
            playstore_df = pd.read_csv(os.path.join(OUTPUT_DIR, "googleplaystore.csv"))
            malware_df = pd.read_csv(os.path.join(OUTPUT_DIR, "Android_Malware_Benign.csv"))
            
            # Clean datasets
            playstore_df = self._clean_playstore_data(playstore_df)
            malware_df = self._clean_malware_data(malware_df)
            
            # Extract all unique permissions from malware dataset
            all_permissions = set()
            for perms in malware_df['permissions']:
                all_permissions.update(perms)
                
            # Map permissions based on app categories
            # This creates a more realistic mapping based on app type
            category_permission_map = {
                'GAME': ['READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'INTERNET', 'ACCESS_NETWORK_STATE'],
                'SOCIAL': ['READ_CONTACTS', 'INTERNET', 'ACCESS_NETWORK_STATE', 'CAMERA', 'RECORD_AUDIO'],
                'PRODUCTIVITY': ['READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'INTERNET'],
                'COMMUNICATION': ['READ_CONTACTS', 'INTERNET', 'ACCESS_NETWORK_STATE', 'READ_SMS', 'SEND_SMS'],
                'PHOTOGRAPHY': ['CAMERA', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE'],
                # Add more categories as needed
            }
            
            # Assign permissions based on category and some randomization
            def assign_permissions(row):
                category = row['Category'].upper()
                base_permissions = category_permission_map.get(category, ['INTERNET', 'ACCESS_NETWORK_STATE'])
                
                # Add some randomization but keep it consistent for each app
                np.random.seed(hash(row['App']) % 2**32)
                
                # Add some random permissions from the malware dataset
                extra_permissions = np.random.choice(list(all_permissions), 
                                                  size=np.random.randint(2, 5),
                                                  replace=False)
                
                return list(set(base_permissions + list(extra_permissions)))
            
            # Apply the permission mapping
            playstore_df['permissions'] = playstore_df.apply(assign_permissions, axis=1)
            
            # Log statistics
            self.logger.info(f"Apps with permissions assigned: {len(playstore_df[playstore_df['permissions'].str.len() > 0])}")
            self.logger.info(f"Average permissions per app: {playstore_df['permissions'].str.len().mean():.2f}")
            
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
        
        # Convert Reviews to numeric
        df['Reviews'] = pd.to_numeric(df['Reviews'], errors='coerce')
        
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
            # Create a copy to avoid the SettingWithCopyWarning
            df = df.copy()
            
            # All columns except 'Label' are permissions
            permission_columns = [col for col in df.columns if col != 'Label']
            
            # Convert wide format (1/0) to list of actual permission names
            df['permissions'] = df[permission_columns].apply(
                lambda x: [col for col, val in x.items() if val == 1], 
                axis=1
            )
            
            # Log statistics to verify permissions are being extracted
            all_permissions = set().union(*df['permissions'])
            self.logger.info(f"Total unique permissions found in malware dataset: {len(all_permissions)}")
            self.logger.info(f"Sample permissions: {list(all_permissions)[:5]}")
            
            return pd.DataFrame({
                'permissions': df['permissions'],
                'is_malware': df['Label']
            })
            
        except Exception as e:
            self.logger.error(f"Error cleaning malware data: {str(e)}")
            raise