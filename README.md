
🛡️ Malware Detection System

This project implements a Machine Learning-Based Malware Detection System using Random Forest Classifier.  
It extracts Portable Executable (PE) file features and predicts whether a given file is malicious or benign.  
The system includes both a training pipeline and a Flask-based web application for live detection.

⚙️ Installation & Setup

1. Clone the Repository:
  -git clone https://github.com/YOUR_USERNAME/maldetection.git
  -cd maldetection
2. Create Virtual Environment:
  -python -m venv venv
  -source venv/bin/activate      # Linux/Mac
  -venv\Scripts\activate         # Windows
3. Install Dependencies:
   -pip install -r requirements.txt

🚀 Usage

1. Train the Model:
   -python train_model.py
2. Run Flask App:
   -python app.py
3.Open your browser at:
  -http://localhost:5000
