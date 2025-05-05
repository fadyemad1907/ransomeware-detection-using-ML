import joblib
import sys

try:
    model_data = joblib.load('ransomware_detector_20250417_074204.joblib')
    print(f"Model type: {type(model_data)}")
    print(f"Model contents: {model_data}")
    
    if isinstance(model_data, dict):
        print("\nDictionary keys:")
        for key in model_data.keys():
            print(f"- {key}")
            if hasattr(model_data[key], 'predict'):
                print(f"  - Has predict method")
            if hasattr(model_data[key], 'transform'):
                print(f"  - Has transform method")
except Exception as e:
    print(f"Error: {str(e)}") 