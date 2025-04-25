from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import numpy as np
import pickle
import re
from database import db, User, PredictionHistory, ContactMessage , FAQQuestion
from functools import wraps

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

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return redirect(url_for('homepage'))

@app.route('/home')
@login_required
def homepage():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('🚫 Username already exists. Please choose another.', 'danger')
            return redirect(url_for('register'))

        # Strong password check
        pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$'
        if not re.match(pattern, password):
            flash('⚠️ Password must be 8+ chars, include 1 uppercase, 1 number, and 1 special character.', 'warning')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('✅ Account created successfully. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    history = PredictionHistory.query.filter_by(user_id=current_user.id).order_by(PredictionHistory.timestamp.desc()).all()
    return render_template('dashboard.html', history=history)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    if not check_password_hash(current_user.password, current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('dashboard'))

    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('dashboard'))

    if len(new_password) < 8:
        flash('New password must be at least 8 characters.', 'danger')
        return redirect(url_for('dashboard'))

    # Save new password
    current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
    db.session.commit()
    flash('Password changed successfully.', 'success')
    return redirect(url_for('dashboard'))

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
@login_required
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        flash('✅ Thanks! We will reach out to you shortly.', 'success')

        # Save to DB
        contact = ContactMessage(name=name, email=email, message=message)
        db.session.add(contact)
        db.session.commit()

        return render_template('contact.html', success=True)
    return render_template('contact.html', success=False)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        new_password = request.form['password']

        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('profile'))

        # Update password
        hashed = generate_password_hash(new_password, method='pbkdf2:sha256')
        current_user.password = hashed
        db.session.commit()
        flash('✅ Password updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=current_user)

@app.route('/faq')
@login_required
def faq():
    return render_template('faq.html')

@app.route('/submit_question', methods=['POST'])
@login_required
def submit_question():
    question = request.form['question']
    if question.strip():
        new_q = FAQQuestion(user_id=current_user.id, question=question)
        db.session.add(new_q)
        db.session.commit()
        flash('✅ Your question has been submitted!', 'success')
    else:
        flash('⚠️ Please enter a question.', 'danger')

    return redirect(url_for('faq'))

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # (Optional) Get data from PredictionHistory
    all_users = User.query.all()
    history = PredictionHistory.query.all()
    return render_template('admin_dashboard.html', users=all_users, history=history)

@app.route('/admin/faqs', methods=['GET', 'POST'])
@login_required
def admin_faqs():
    if current_user.role != 'admin':
        return redirect(url_for('homepage'))

    faqs = FAQQuestion.query.order_by(FAQQuestion.timestamp.desc()).all()

    if request.method == 'POST':
        faq_id = request.form['faq_id']
        answer = request.form['answer']

        faq = FAQQuestion.query.get(faq_id)
        faq.answer = answer
        db.session.commit()
        flash('Answer submitted successfully.', 'success')
        return redirect(url_for('admin_faqs'))

    return render_template('admin-faqs.html', faqs=faqs)


@app.route('/admin/messages')
@login_required
@admin_required
def admin_messages():
    messages = ContactMessage.query.order_by(ContactMessage.timestamp.desc()).all()
    return render_template('admin_messages.html', messages=messages)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('✅ You have been logged out successfully.', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)


