# Android App Risk Analyzer

This project is designed to analyze the risk of Android applications based on their permissions, size anomalies, and other factors. It fetches datasets from Kaggle, cleans and processes the data, performs risk analysis, and generates visualizations to help understand the risk distribution among different app categories.

## Features

- **Data Fetching and Cleaning**: 
  - Downloads datasets from Kaggle.
  - Cleans and preprocesses the data to ensure it is ready for analysis.
  - Handles missing values, converts data types, and assigns permissions based on app categories.

- **Risk Analysis**:
  - Calculates risk scores for each app based on permissions, size anomalies, and other factors.
  - Uses a weighted scoring system to combine different risk factors into a final risk score.
  - Provides detailed logging and error handling to ensure robustness.

- **Visualizations**:
  - Generates heatmaps to show the correlation between different permissions.
  - Creates bar plots to display the distribution of risk scores across different app categories.
  - Produces scatter plots to visualize the relationship between app size, risk score, and number of reviews.

## Project Structure

- `config.py`: Configuration file containing constants and settings for the project.
- `data_loader.py`: Contains the `DataLoader` class responsible for fetching, cleaning, and preprocessing the datasets.
- `risk_analyzer.py`: Contains the `RiskAnalyzer` class responsible for calculating risk scores based on various factors.
- `visualizer.py`: Contains the `Visualizer` class responsible for generating visualizations.
- `main.py`: The main script that orchestrates the data loading, risk analysis, and visualization generation.
- `requirements.txt`: Lists the dependencies required to run the project.
- `output/`: Directory where the cleaned data, analysis reports, and visualizations are saved.

## Datasets

The project uses the following datasets from Kaggle:
- Google Play Store Apps: `lava18/google-play-store-apps`
- Android Malware Detection Dataset: `dannyrevaldo/android-malware-detection-dataset`

## Risk Scoring

The risk scoring system considers the following factors:
- **Permissions**: The presence of certain permissions that are more common in malware apps.
- **Size Anomalies**: Deviations in app size compared to the average size of apps in the same category.
- **Other Factors**: Additional factors such as review patterns and category anomalies can be incorporated.

## Visualizations

The project generates the following visualizations:
- **Permission Heatmap**: Shows the correlation between different permissions.
- **Category Distribution**: Displays the distribution of risk scores across different app categories.
- **Risk Scatter Plot**: Visualizes the relationship between app size, risk score, and number of reviews.

## License

This project is licensed under the Creative Commons Attribution 3.0 Unported License. See the [LICENSE](output/license.txt) file for details.