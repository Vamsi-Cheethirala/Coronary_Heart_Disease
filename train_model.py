import pandas as pd
import numpy as np
import pickle

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier

# Load dataset
heartData = pd.read_csv("coronary heart disease.csv")

# Clean data
heartData = heartData.drop_duplicates()
X = heartData.drop(['target'], axis=1)
y = heartData['target']

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.30, random_state=0)

# Train models
rf_model = RandomForestClassifier(n_estimators=10, random_state=0)
rf_model.fit(X_train, y_train)

logistic_model = LogisticRegression()
logistic_model.fit(X_train, y_train)

dt_classifier = DecisionTreeClassifier(max_features=13, random_state=0)
dt_classifier.fit(X_train, y_train)

knn_classifier = KNeighborsClassifier(n_neighbors=11)
knn_classifier.fit(X_train, y_train)

# Save models into a list
all_models = [rf_model, logistic_model, dt_classifier, knn_classifier]

# Save to models.pkl
with open("models.pkl", 'wb') as file:
    pickle.dump(all_models, file)

print("✅ models.pkl saved successfully!")
