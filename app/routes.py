from flask import render_template, request, redirect, url_for, flash, session, current_app, make_response
from flask_mail import Message
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from . import app, db, mail
from .models import User, Donation
from .utils import fetch_unsplash_image  # Import the utility function
import random
import string

def generate_verification_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

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
            return render_template('signup.html')

        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('User signed up successfully!', 'success')
        return redirect(url_for('login'))
    
    background_image_url = fetch_unsplash_image('signup')
    return render_template('signup.html', background_image_url=background_image_url)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            verification_code = generate_verification_code()
            session['verification_code'] = verification_code
            session['username'] = user.username

            msg = Message('Your Verification Code', 
                          sender=current_app.config['MAIL_USERNAME'], 
                          recipients=[user.email])
            msg.body = f'Your verification code is {verification_code}'
            try:
                mail.send(msg)
                flash('Verification code sent to your email', 'info')
                return redirect(url_for('verify'))
            except Exception as e:
                flash(f'Failed to send email: {e}', 'error')
                return render_template('login.html')
        else:
            flash('Invalid credentials', 'error')
            return render_template('login.html')
    background_image_url = fetch_unsplash_image('charity')
    return render_template('login.html', background_image_url=background_image_url)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        code = request.form.get('code')
        if code == session.get('verification_code'):
            access_token = create_access_token(identity=session['username'])
            session.pop('verification_code', None)
            response = make_response(redirect(url_for('profile')))
            response.set_cookie('access_token', access_token, httponly=True)
            flash('Login successful', 'success')
            return response
        flash('Invalid verification code', 'error')
    return render_template('verify.html')

@app.route('/profile')
def profile():
    try:
        access_token = request.cookies.get('access_token')

        if access_token:
            from flask_jwt_extended import decode_token
            decoded_token = decode_token(access_token)
            current_user = decoded_token['sub']

            user = User.query.filter_by(username=current_user).first()
            if user is None:
                flash('User not found.', 'error')
                return redirect(url_for('login'))

            donations = Donation.query.filter_by(user_id=user.id).all()
            return render_template('profile.html', user=user, donations=donations)
        else:
            flash('Unauthorized access. Please log in again.', 'error')
            return redirect(url_for('login'))
    except Exception as e:
        flash('Unauthorized access. Please log in again.', 'error')
        return redirect(url_for('login'))

@app.route('/assistance')
def assistance():
    return render_template('assistance.html')

@app.route('/volunteer')
def volunteer():
    volunteer_image = fetch_unsplash_image('volunteer')
    community_image = fetch_unsplash_image('community')
    helping_image = fetch_unsplash_image('helping')
    return render_template('volunteer.html', volunteer_image=volunteer_image, community_image=community_image, helping_image=helping_image)


@app.route('/profile/donor')
def donor_profile():
    if 'user_id' not in session:
        flash('You must be logged in to access this page.', 'error')
        return redirect(url_for('login'))
    return render_template('donor_profile.html')

@app.route('/donation')
def donation():
    education_image = fetch_unsplash_image('education')
    health_image = fetch_unsplash_image('health')
    environment_image = fetch_unsplash_image('environment')
    animals_image = fetch_unsplash_image('animals')
    hunger_image = fetch_unsplash_image('hunger')
    water_image = fetch_unsplash_image('water')
    shelter_image = fetch_unsplash_image('shelter')
    clothes_image = fetch_unsplash_image('clothes')
    skills_image = fetch_unsplash_image('skills')
    return render_template('donation.html', education_image=education_image, health_image=health_image, environment_image=environment_image, animals_image=animals_image, hunger_image=hunger_image, water_image=water_image, shelter_image=shelter_image, clothes_image=clothes_image, skills_image=skills_image)


@app.route('/')
def index():
    nature_image = fetch_unsplash_image('nature')
    charity_image = fetch_unsplash_image('charity')
    volunteer_image = fetch_unsplash_image('volunteer')
    community_image = fetch_unsplash_image('community')

    return render_template('index.html', nature_image=nature_image, charity_image=charity_image, volunteer_image=volunteer_image, community_image=community_image)
