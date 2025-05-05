import joblib
import pickle
import numpy as np
import h5py  # For HDF5 format
import json

def try_load_with_joblib():
    print("Trying to load with joblib...")
    try:
        model = joblib.load('ransomware_detector_20250417_074204.joblib')
        print("Successfully loaded with joblib!")
        return model
    except Exception as e:
        print(f"Failed with joblib: {str(e)}")
        return None

def try_load_with_pickle():
    print("\nTrying to load with pickle...")
    try:
        with open('ransomware_detector_20250417_074204.joblib', 'rb') as f:
            model = pickle.load(f)
        print("Successfully loaded with pickle!")
        return model
    except Exception as e:
        print(f"Failed with pickle: {str(e)}")
        return None

def try_load_with_h5py():
    print("\nTrying to load with h5py...")
    try:
        with h5py.File('ransomware_detector_20250417_074204.joblib', 'r') as f:
            print("File opened with h5py, contents:")
            for key in f.keys():
                print(f"Key: {key}")
            return f
    except Exception as e:
        print(f"Failed with h5py: {str(e)}")
        return None

def try_load_with_json():
    print("\nTrying to load with json...")
    try:
        with open('ransomware_detector_20250417_074204.joblib', 'r', encoding='utf-8') as f:
            data = json.load(f)
            print("Successfully loaded with json!")
            return data
    except Exception as e:
        print(f"Failed with json: {str(e)}")
        return None

def main():
    print("Attempting different methods to load the model...")
    
    # Try different loading methods
    model = try_load_with_joblib()
    if model is None:
        model = try_load_with_pickle()
    if model is None:
        model = try_load_with_h5py()
    if model is None:
        model = try_load_with_json()
    
    if model is not None:
        print("\nModel loaded successfully!")
        print(f"Model type: {type(model)}")
        if hasattr(model, 'predict'):
            print("Model has predict method")
        if hasattr(model, 'predict_proba'):
            print("Model has predict_proba method")
        if isinstance(model, dict):
            print("Model is a dictionary with keys:", model.keys())
    else:
        print("\nFailed to load model with all methods")

if __name__ == "__main__":
    main() 