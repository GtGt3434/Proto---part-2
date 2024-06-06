from flask import render_template, request, redirect, url_for, flash, session
from . import app, db
from .models import User, Donation

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('signup.html')  

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email is already registered. Please use a different one or login.', 'error')
            return render_template('signup.html')  # Same here

        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('User signed up successfully!', 'success')
        return redirect(url_for('login_page'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Add logic here to verify user credentials
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/assistance')
def assistance():
    return render_template('assistance.html')

@app.route('/volunteer')
def volunteer():
    return render_template('volunteer.html')


@app.route('/profile/donor')
def donor_profile():
    if 'user_id' not in session:
        flash('You must be logged in to access this page.', 'error')
        return redirect(url_for('login'))
    # Fetch user details and donations if logged in
    return render_template('donor_profile.html')


@app.route('/donation')
def donation():
    return render_template('donation.html')

@app.route('/')
def index():
    return render_template('index.html')


