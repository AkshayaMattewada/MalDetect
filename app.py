# app.py
from flask import Flask, render_template, request
from feature_extractor import extract_pe_header_features
import pandas as pd
import joblib
import os
import tempfile

app = Flask(__name__)
model = joblib.load('C:\\Users\\venuv\\maldetect\\models\\random_forest_model.pkl')

with open("C:\\Users\\venuv\\maldetect\\models\\feature_names.txt", "r") as f:
    feature_order = [line.strip() for line in f.readlines()]

@app.route('/')
def index():
    return render_template('index.html')
@app.route('/predict', methods=['POST'])
def predict():
    if 'file' not in request.files:
        return "⚠️ No file uploaded."

    file = request.files['file']

    if file.filename == '':
        return "⚠️ No file selected."

    # Save file manually to avoid WinError
    temp_dir = tempfile.gettempdir()
    filepath = os.path.join(temp_dir, file.filename)
    file.save(filepath)

    # Extract features
    features = extract_pe_header_features(filepath)

    # Clean up
    try:
        os.remove(filepath)
    except Exception as e:
        print(f"⚠️ Could not delete file: {e}")

    if features is None:
        return render_template('result.html', result="⚠️ Could not extract features. Not a valid PE file.")

    # Align features
    input_df = pd.DataFrame([[features.get(feat, 0) for feat in feature_order]], columns=feature_order)
    prediction = model.predict(input_df)[0]
    result = "🛡️ Benign File" if prediction == 0 else "☠️ Malware Detected!"

    return render_template('result.html', result=result)


if __name__ == '__main__':
    app.run(debug=True)
