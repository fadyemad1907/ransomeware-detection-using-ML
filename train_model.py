import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.feature_selection import SelectFromModel
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import joblib
import logging
from datetime import datetime
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_and_preprocess_data():
    """Load and preprocess the dataset"""
    try:
        # Load the dataset
        df = pd.read_csv('data_file.csv')
        logger.info(f"Dataset loaded successfully. Shape: {df.shape}")
        
        # List all available features
        all_features = [
            'Machine', 'DebugSize', 'DebugRVA', 'MajorImageVersion',
            'MajorOSVersion', 'ExportRVA', 'ExportSize', 'IatVRA',
            'MajorLinkerVersion', 'MinorLinkerVersion', 'NumberOfSections',
            'SizeOfStackReserve', 'DllCharacteristics', 'ResourceSize',
            'BitcoinAddresses'
        ]
        
        # Ensure all features exist
        missing_features = [f for f in all_features if f not in df.columns]
        if missing_features:
            logger.warning(f"Missing features: {missing_features}")
            all_features = [f for f in all_features if f in df.columns]
        
        # Convert md5Hash to numerical value
        if 'md5Hash' in df.columns:
            df['md5Hash_numeric'] = df['md5Hash'].apply(lambda x: int(x[:8], 16) if pd.notnull(x) else 0)
            all_features.append('md5Hash_numeric')
        
        # Add derived features
        df['SizeRatio'] = df['ResourceSize'] / (df['DebugSize'] + 1)
        df['TotalSize'] = df['ResourceSize'] + df['DebugSize'] + df['SizeOfStackReserve']
        df['DebugSize_log'] = np.log1p(df['DebugSize'])
        all_features.extend(['SizeRatio', 'TotalSize', 'DebugSize_log'])
        
        # Handle missing values
        df[all_features] = df[all_features].fillna(0)
        
        # Prepare features and target
        X = df[all_features]
        y = df['Benign']
        
        logger.info(f"Final feature set: {all_features}")
        logger.info(f"Dataset shape after preprocessing: {X.shape}")
        
        return X, y, all_features
        
    except Exception as e:
        logger.error(f"Error in data preprocessing: {str(e)}")
        raise

def train_model(X, y, feature_names):
    """Train the Random Forest model with extensive hyperparameter tuning"""
    try:
        # Create a pipeline with feature selection and model
        pipeline = Pipeline([
            ('scaler', StandardScaler()),
            ('feature_selection', SelectFromModel(
                RandomForestClassifier(n_estimators=100, random_state=42),
                max_features=15
            )),
            ('classifier', RandomForestClassifier(random_state=42))
        ])
        
        # Define the parameter grid for extensive tuning
        param_grid = {
            'classifier__n_estimators': [2000],  # Only test 2000 trees as we've done 500 and 1000
            'classifier__max_depth': [None],     # Only test unlimited depth as we've done 15, 20, 25
            'classifier__min_samples_split': [2, 5, 10],
            'classifier__min_samples_leaf': [1, 2, 4],
            'classifier__max_features': ['sqrt', 'log2'],
            'classifier__bootstrap': [True, False],
            'classifier__class_weight': ['balanced', 'balanced_subsample'],
            'classifier__criterion': ['gini', 'entropy']
        }
        
        # Create cross-validation object
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        
        # Perform grid search with cross-validation
        grid_search = GridSearchCV(
            pipeline,
            param_grid,
            cv=cv,
            scoring='roc_auc',
            n_jobs=-1,
            verbose=2,
            return_train_score=True
        )
        
        logger.info("Starting model training with hyperparameter tuning...")
        grid_search.fit(X, y)
        
        # Get the best model
        best_model = grid_search.best_estimator_
        
        # Log the best parameters
        logger.info("Best parameters found:")
        for param, value in grid_search.best_params_.items():
            logger.info(f"{param}: {value}")
        
        # Evaluate the model
        y_pred = best_model.predict(X)
        y_pred_proba = best_model.predict_proba(X)[:, 1]
        
        metrics = {
            'accuracy': accuracy_score(y, y_pred),
            'precision': precision_score(y, y_pred),
            'recall': recall_score(y, y_pred),
            'f1': f1_score(y, y_pred),
            'roc_auc': roc_auc_score(y, y_pred_proba)
        }
        
        logger.info("Model performance metrics:")
        for metric, value in metrics.items():
            logger.info(f"{metric}: {value:.4f}")
        
        # Get feature importance
        feature_importance = best_model.named_steps['classifier'].feature_importances_
        feature_importance_dict = dict(zip(feature_names, feature_importance))
        
        logger.info("Feature importance:")
        for feature, importance in sorted(feature_importance_dict.items(), key=lambda x: x[1], reverse=True):
            logger.info(f"{feature}: {importance:.4f}")
        
        return best_model, metrics, feature_importance_dict
        
    except Exception as e:
        logger.error(f"Error in model training: {str(e)}")
        raise

def save_model(model, metrics, feature_importance, feature_names):
    """Save the trained model and its metadata"""
    try:
        # Create timestamp for filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save the model
        model_filename = f'ransomware_detector_{timestamp}.joblib'
        joblib.dump({
            'model': model,
            'metrics': metrics,
            'feature_importance': feature_importance,
            'feature_names': feature_names,
            'timestamp': timestamp
        }, model_filename)
        
        logger.info(f"Model saved as {model_filename}")
        
    except Exception as e:
        logger.error(f"Error saving model: {str(e)}")
        raise

def main():
    """Main function to run the training process"""
    try:
        # Load and preprocess data
        X, y, feature_names = load_and_preprocess_data()
        
        # Train the model
        model, metrics, feature_importance = train_model(X, y, feature_names)
        
        # Save the model
        save_model(model, metrics, feature_importance, feature_names)
        
        logger.info("Training completed successfully!")
        
    except Exception as e:
        logger.error(f"Error in main function: {str(e)}")
        raise

if __name__ == "__main__":
    main() 