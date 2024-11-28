import logging
import os
import numpy as np
from data_loader import DataLoader
from risk_analyzer import RiskAnalyzer
from visualizer import Visualizer
from config import *

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('app_analysis.log'),
            logging.StreamHandler()
        ]
    )

def main():
    # Setup
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Create output directories
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(VISUALIZATIONS_DIR, exist_ok=True)

    try:
        # Initialize components
        data_loader = DataLoader()
        logger.info("Fetching datasets...")
        data_loader.fetch_datasets()
        
        logger.info("Loading and cleaning data...")
        playstore_df, malware_df = data_loader.load_and_clean_data()
        
        risk_analyzer = RiskAnalyzer(malware_df)
        visualizer = Visualizer()

        # Perform analysis
        logger.info("Performing risk analysis...")
        playstore_df['Risk_Score'] = playstore_df.apply(
            lambda row: risk_analyzer.calculate_risk_score({
                'permissions': row['permissions'] if isinstance(row['permissions'], list) else [],
                'size': row['Size'],
                'category_sizes': playstore_df[playstore_df['Category'] == row['Category']]['Size']
            }), axis=1
        )

        # Add Permission_Count column
        playstore_df['Permission_Count'] = playstore_df['permissions'].apply(lambda x: len(x) if isinstance(x, list) else 0)

        # Debug output
        logger.debug(f"Play Store DataFrame with Risk Score: {playstore_df[['App', 'permissions', 'Permission_Count', 'Risk_Score']].head()}")

        # Generate visualizations
        logger.info("Generating visualizations...")
        numeric_columns = playstore_df.select_dtypes(include=[np.number])
        permission_correlation = numeric_columns.corr()
        visualizer.create_permission_heatmap(permission_correlation, os.path.join(VISUALIZATIONS_DIR, 'permission_heatmap.png'))
        
        category_distribution = playstore_df.groupby('Category')['Risk_Score'].mean().reset_index()
        visualizer.create_category_distribution(category_distribution, os.path.join(VISUALIZATIONS_DIR, 'category_distribution.png'))
        
        visualizer.create_risk_scatter(playstore_df, os.path.join(VISUALIZATIONS_DIR, 'risk_scatter.html'))

        # Save analysis results
        logger.info("Saving analysis results...")
        playstore_df.to_csv(os.path.join(REPORTS_DIR, 'playstore_risk_analysis.csv'), index=False)
        malware_df.to_csv(os.path.join(REPORTS_DIR, 'malware_data_cleaned.csv'), index=False)

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()