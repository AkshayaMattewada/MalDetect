# train_model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Load the dataset
df = pd.read_csv("C:\\Users\\venuv\\maldetect\\datasets\\PE_Header.csv")

# Drop non-numeric columns
df.drop(['SHA256'], axis=1, inplace=True)

# Drop missing values (if any)
df.dropna(inplace=True)

# Separate features and label
X = df.drop('Type', axis=1)
y = df['Type']

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the Random Forest model
model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')

model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("✅ Model trained!")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Save the model
joblib.dump(model, 'models/random_forest_model.pkl')
print("\n📦 Model saved to models/random_forest_model.pkl")
# Save the feature list
with open("models/feature_names.txt", "w") as f:
    for col in X.columns:
        f.write(col + "\n")
print("📄 Feature list saved to models/feature_names.txt")
