# predict.py
import joblib
import pandas as pd
import sys
from feature_extractor import extract_pe_header_features

# Load the trained model
model = joblib.load("C:\\Users\\venuv\\maldetect\\models\\random_forest_model.pkl")

# Get .exe file path from command-line argument
if len(sys.argv) < 2:
    print("Usage: python predict.py <path_to_exe_file>")
    exit()

file_path = sys.argv[1]

# Extract features
features = extract_pe_header_features(file_path)

if features:
    # Convert to DataFrame (model expects 2D array)
    # Load expected feature order
    with open("models/feature_names.txt", "r") as f:
        expected_features = [line.strip() for line in f.readlines()]

# Build DataFrame with correct column order
    input_df = pd.DataFrame([[features.get(feat, 0) for feat in expected_features]], columns=expected_features)

    prediction = model.predict(input_df)[0]
    print(f"🧪 Prediction: {'Malware' if prediction == 1 else 'Benign'}")
else:
    print("⚠️ Could not extract features from file.")
