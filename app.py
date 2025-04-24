from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import numpy as np
import pickle

from database import db, User, PredictionHistory, ContactMessage

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Load your trained model (make sure 'models.pkl' is in the same folder)
with open("models.pkl", "rb") as f:
    models = pickle.load(f)
    model = models[0]  # Using RandomForestClassifier

@app.route('/')
def home():
    return redirect(url_for('homepage'))

@app.route('/home')
def homepage():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('form'))
        return 'Invalid credentials'
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if len(password) < 4:
            return "Password must be at least 4 characters long."

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/form', methods=['GET', 'POST'])
@login_required
def form():
    if request.method == 'POST':
        features = np.array([float(x) for x in request.form.values()]).reshape(1, -1)

        model_names = ["Random Forest", "Logistic Regression", "Decision Tree", "KNN"]
        probabilities = []

        for m in models:
            prob = round(m.predict_proba(features)[0][1] * 100, 2)  # Probability of heart disease (label 1)
            probabilities.append(prob)

        main_prediction = models[0].predict(features)[0]
        main_probability = probabilities[0]

        # Save full result from main model to DB
        input_str = ", ".join(request.form.values())
        full_result = f"{main_prediction} ({main_probability}%)"
        history = PredictionHistory(user_id=current_user.id, input_data=input_str, result=full_result)
        db.session.add(history)
        db.session.commit()

        return render_template('result.html',
                               result=main_prediction,
                               probability=main_probability,
                               model_names=model_names,
                               probabilities=probabilities)

    return render_template('form.html')


@app.route('/history')
@login_required
def history():
    history_data = PredictionHistory.query.filter_by(user_id=current_user.id).order_by(PredictionHistory.timestamp.desc()).all()
    return render_template('history.html', history=history_data)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # Save to DB
        contact = ContactMessage(name=name, email=email, message=message)
        db.session.add(contact)
        db.session.commit()

        return render_template('contact.html', success=True)
    return render_template('contact.html', success=False)


@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)


