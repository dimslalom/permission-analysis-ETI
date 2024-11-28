import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import plotly.express as px
from config import *
import logging

class Visualizer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        try:
            plt.style.use(PLOT_STYLE)
        except Exception as e:
            self.logger.warning(f"Could not set style {PLOT_STYLE}, using default style. Error: {str(e)}")
            # Set a simple default style
            plt.style.use('default')
        
        # Set seaborn style as well
        sns.set_theme()
        
    def create_permission_heatmap(self, permission_correlation, output_path):
        plt.figure(figsize=(12, 8), dpi=DPI)
        sns.heatmap(permission_correlation, annot=True, cmap='coolwarm')
        plt.title('Permission Correlation Heatmap')
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()

    def create_category_distribution(self, category_data, output_path):
        plt.figure(figsize=(15, 6), dpi=DPI)
        sns.barplot(data=category_data, x='Category', y='Risk_Score')
        plt.xticks(rotation=45)
        plt.title('Risk Score Distribution by Category')
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()

    def create_risk_scatter(self, df, output_path):
        try:
            # Create a copy and handle missing values properly
            plot_df = df.copy()
            
            # Convert Reviews to numeric and fill NaN with median
            plot_df['Reviews'] = pd.to_numeric(plot_df['Reviews'], errors='coerce')
            plot_df['Reviews'] = plot_df['Reviews'].fillna(plot_df['Reviews'].median())
            
            # Log some statistics for debugging
            self.logger.info(f"Reviews range: {plot_df['Reviews'].min()} to {plot_df['Reviews'].max()}")
            self.logger.info(f"Number of apps with permissions: {len(plot_df[plot_df['permissions'].str.len() > 0])}")
            
            # Create scatter plot with cleaned data
            fig = px.scatter(
                plot_df,
                x='Size',
                y='Risk_Score',
                color='Category',
                size='Reviews',
                hover_data=['App', 'permissions'],
                title='App Risk Analysis'
            )
            fig.write_html(output_path)
        except Exception as e:
            self.logger.error(f"Error creating risk scatter plot: {str(e)}")
            raise