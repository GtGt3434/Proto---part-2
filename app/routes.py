from flask import render_template, request, redirect, url_for, flash, session, current_app, make_response, jsonify
from flask_mail import Message
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from flask_login import login_required, current_user, login_user, logout_user
from . import app, db, mail
from .models import User, Donation, DonationCategory, Volunteer, VolunteerReport, VolunteerOpportunity, VolunteerSignup, HelpRequest, VolunteerHours, CreditCard
from .utils import fetch_unsplash_image, extract_text_from_file  # Import the utility function
import random
import string
from .decorators import role_required
from .utils import match_opportunities, evaluate_assistance_request, allowed_file
import os
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer



def generate_verification_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

# routes.py

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

        # Redirect to add credit card page if role is 'donor' and no credit card is added
        if role == 'donor' and not new_user.has_credit_card:
            login_user(new_user)
            return redirect(url_for('add_credit_card'))

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
                next_url = request.args.get('next')
                return redirect(url_for('verify', next=next_url))
            except Exception as e:
                flash(f'Failed to send email: {e}', 'error')
                return render_template('login.html')
        else:
            flash('Invalid credentials', 'error')
            return render_template('login.html')
    background_image_url = fetch_unsplash_image('charity')
    return render_template('login.html', background_image_url=background_image_url)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    # Create the serializer within the route
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate a password reset token
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Send email
            msg = Message('Password Reset Request',
                          sender=current_app.config['MAIL_USERNAME'],
                          recipients=[email])
            msg.body = f'Please click the link to reset your password: {reset_url}'
            mail.send(msg)
            
            flash('A password reset email has been sent.', 'info')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email address.', 'error')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Create the serializer within the route
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

    try:
        # Deserialize the token to get the email
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception as e:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            # Set the new password
            user.set_password(password)
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))
        else:
            flash('User not found.', 'error')

    return render_template('reset_password.html', token=token)

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
            user = User.query.filter_by(username=session['username']).first()
            login_user(user)

            # Check if user is a donor and hasn't added a credit card yet
            if user.role == 'donor' and not user.has_credit_card:
                return redirect(url_for('add_credit_card'))

            next_url = request.args.get('next')
            if next_url:
                response = make_response(redirect(next_url))
            return response

        flash('Invalid verification code', 'error')
    return render_template('verify.html')


@app.route('/profile')
@login_required
def profile():
    try:
        # Fetching the access token from cookies
        access_token = request.cookies.get('access_token')
        current_app.logger.info(f"Access Token: {access_token}")  # Log the access token

        if not access_token:
            flash('Unauthorized access. Please log in again.', 'error')
            return redirect(url_for('login'))
        
        from flask_jwt_extended import decode_token
        try:
            decoded_token = decode_token(access_token)
            current_app.logger.info(f"Decoded Token: {decoded_token}")  # Log the decoded token
        except Exception as decode_error:
            current_app.logger.error(f"Error decoding token: {decode_error}", exc_info=True)
            flash('Unauthorized access. Please log in again.', 'error')
            return redirect(url_for('login'))

        current_username = decoded_token.get('sub')
        current_app.logger.info(f"Current Username: {current_username}")  # Log the username

        # Fetching user by username
        user = User.query.filter_by(username=current_username).first()
        current_app.logger.info(f"User Found: {user}")  # Log the found user
        
        if user is None:
            flash('User not found.', 'error')
            return redirect(url_for('login'))

        if user.role == 'donor':
            try:
                donations = Donation.query.filter_by(user_id=user.id).all()
                total_donated = sum(donation.amount for donation in donations)
                current_app.logger.info(f"Total Donated by user {user.id}: {total_donated}")
                return render_template('profile.html', user=user, donations=donations, total_donated=total_donated)
            except Exception as e:
                current_app.logger.error(f"Error fetching donations: {e}", exc_info=True)
                flash('Error loading donations. Please try again later.', 'error')
                return redirect(url_for('profile'))

        elif user.role == 'volunteer':
            try:
                volunteer_reports = VolunteerReport.query.filter_by(user_id=user.id).all()
                volunteer_hours = VolunteerHours.query.filter_by(user_id=user.id).all()
                verified_hours = sum(hours.hours_worked for hours in volunteer_hours if hours.verified > 0)
                current_app.logger.info(f"Verified Hours for user {user.id}: {verified_hours}")
                
                reports_with_opportunities = []
                for report in volunteer_reports:
                    signups = VolunteerSignup.query.filter_by(report_id=report.id).all()
                    current_app.logger.info(f"Signups for Report {report.id}: {signups}")  # Log signups
                    opportunities = [signup.opportunity for signup in signups]
                    current_app.logger.info(f"Opportunities for Report {report.id}: {opportunities}")  # Log opportunities
                    reports_with_opportunities.append({'report': report, 'opportunities': opportunities})
                
                return render_template('profile.html', user=user, reports_with_opportunities=reports_with_opportunities, volunteer_hours=volunteer_hours, verified_hours=verified_hours)
            except Exception as e:
                current_app.logger.error(f"Error fetching volunteer reports: {e}", exc_info=True)
                flash('Error loading volunteer reports. Please try again later.', 'error')
                return redirect(url_for('profile'))

        elif user.role == 'aid_seeker':
            try:
                help_requests = HelpRequest.query.filter_by(user_id=user.id).all()
                current_app.logger.info(f"Help Requests for user {user.id}: {help_requests}")  # Log help requests
                return render_template('profile.html', user=user, help_requests=help_requests)
            except Exception as e:
                current_app.logger.error(f"Error fetching help requests: {e}", exc_info=True)
                flash('Error loading help requests. Please try again later.', 'error')
                return redirect(url_for('profile'))
        else:
            flash('Invalid user role.', 'error')
            return redirect(url_for('login'))
    
    except Exception as e:
        current_app.logger.error(f"Exception in profile route: {e}", exc_info=True)
        flash('An error occurred. Please try again later.', 'error')
        return redirect(url_for('login'))


@app.route('/assistance', methods=['GET', 'POST'])
@login_required
def assistance():
    if current_user.role != 'aid_seeker':
        flash('You have to be an aid seeker to access this page.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            # Collect form data
            full_name = request.form.get('full-name')
            age = request.form.get('age')
            gender = request.form.get('gender')
            contact = request.form.get('contact')
            assistance_type = request.form.get('assistance-type')
            description = request.form.get('assistance-description')
            income = request.form.get('income')
            expenses = request.form.get('expenses')
            assistance_amount = request.form.get('assistance-amount')
            confirm = request.form.get('confirm')

            extracted_texts = []
            document_paths = []

            # Handle file uploads
            if 'supporting-docs' in request.files:
                files = request.files.getlist('supporting-docs')
                for file in files:
                    if file and allowed_file(file.filename):
                        extracted_text = extract_text_from_file(file)
                        extracted_texts.append(extracted_text)
                        filename = secure_filename(file.filename)
                        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                        file.save(file_path)
                        document_paths.append(file_path)

            combined_texts = "\n\n".join(extracted_texts)

            # Evaluate the request and generate a summary if truthful
            status, evaluation_notes, summary = evaluate_assistance_request(
                full_name, age, gender, contact, assistance_type, description, 
                income, expenses, assistance_amount, combined_texts
            )

            # Log the evaluation result
            current_app.logger.info(f"Evaluation result: {evaluation_notes}")

            # Save the help request with the generated summary
            new_request = HelpRequest(
                user_id=current_user.id,
                full_name=full_name,
                age=age,
                gender=gender,
                contact_number=contact,
                assistance_type=assistance_type,
                description=description,
                income=income,
                expenses=expenses,
                assistance_amount=assistance_amount,
                evaluation_status=status,
                evaluation_notes=evaluation_notes,
                document_paths=",".join(document_paths),
                summary=summary  # Store the generated summary
            )
            db.session.add(new_request)
            db.session.commit()

            flash('Your request has been submitted successfully!', 'success')
            return redirect(url_for('profile'))

        except Exception as e:
            # Log any exceptions and rollback the transaction
            current_app.logger.error(f"Exception during assistance request processing: {e}", exc_info=True)
            db.session.rollback()
            flash('An error occurred while processing your request. Please try again.', 'danger')
            return redirect(url_for('assistance'))

    return render_template('assistance.html')

@app.route('/get_aid_request_details/<int:aid_request_id>', methods=['GET'])
def get_aid_request_details(aid_request_id):
    aid_request = HelpRequest.query.get_or_404(aid_request_id)
    return jsonify({
        'full_name': aid_request.full_name,
        'description': aid_request.description,
        'summary': aid_request.summary
    })


"""@app.route('/profile/donor')
def donor_profile():
    if 'user_id' not in session:
        flash('You must be logged in to access this page.', 'error')
        return redirect(url_for('login'))
    return render_template('donor_profile.html')"""

@app.route('/donation', methods=['GET', 'POST'])
def donation():
    # Check if a POST request was made
    if request.method == 'POST':
        amount = request.form.get('amount')

        # Validate the donation amount
        if amount and float(amount) > 0:
            if current_user.is_authenticated:
                try:
                    # Convert amount to float for proper handling
                    donation_amount = float(amount)
                    
                    # Add a new donation record for general donations or category-specific
                    new_donation = Donation(amount=donation_amount, user_id=current_user.id)
                    db.session.add(new_donation)
                    db.session.commit()
                    flash('Thank you for your donation!', 'success')
                    return redirect(url_for('profile'))
                except Exception as e:
                    db.session.rollback()
                    current_app.logger.error(f"Error processing donation: {e}")
                    flash('An error occurred while processing your donation. Please try again.', 'danger')
            else:
                flash('You need to log in to make a donation.', 'danger')
                return redirect(url_for('login'))
        else:
            flash('Please enter a valid amount.', 'danger')

    # Fetch the prioritized categories for Israel first
    israel_categories = DonationCategory.query.filter(DonationCategory.title.in_(['Buildings', 'Army: Clothes, Food…', 'Companies'])).all()

    # Fetch all other donation categories
    other_categories = DonationCategory.query.filter(~DonationCategory.title.in_(['Buildings', 'Army: Clothes, Food…', 'Companies'])).all()

    # Combine prioritized categories with other categories
    categories = israel_categories + other_categories

    # Fetch images for all categories
    for category in categories:
        category.image_url = fetch_unsplash_image(category.image_keyword)

    # Fetch aid requests that are marked as 'Likely Truthful'
    aid_requests = HelpRequest.query.filter_by(evaluation_status='Likely Truthful').all()

    # Render the donation template with categories and aid requests
    return render_template('donation.html', categories=categories, aid_requests=aid_requests)


@app.route('/')
def index():
    nature_image = fetch_unsplash_image('nature')
    charity_image = fetch_unsplash_image('charity')
    volunteer_image = fetch_unsplash_image('volunteer')
    community_image = fetch_unsplash_image('community')

    # Fetch top donors
    top_donors = (
        db.session.query(User.username, db.func.sum(Donation.amount).label('total_donated'))
        .join(Donation, Donation.user_id == User.id)
        .group_by(User.id)
        .order_by(db.desc('total_donated'))
        .limit(10)
        .all()
    )

    # Fetch top volunteers
    top_volunteers = (
        db.session.query(User.username, db.func.sum(VolunteerHours.hours_worked).label('total_hours'))
        .join(VolunteerHours, VolunteerHours.user_id == User.id)
        .filter(VolunteerHours.verified > 0)
        .group_by(User.id)
        .order_by(db.desc('total_hours'))
        .limit(10)
        .all()
    )

    return render_template(
        'index.html',
        nature_image=nature_image,
        charity_image=charity_image,
        volunteer_image=volunteer_image,
        community_image=community_image,
        top_donors=top_donors,
        top_volunteers=top_volunteers
    )

@app.route('/donation/<int:category_id>', methods=['GET', 'POST'])
@role_required('donor', 'You must be a donor to access this page.')
def donation_detail(category_id):
    category = DonationCategory.query.get_or_404(category_id)
    category.image_url = fetch_unsplash_image(category.image_keyword)
    
    if request.method == 'POST':
        amount = request.form.get('amount')
        if amount:
            try:
                # Log the amount and user details
                app.logger.info(f"User {current_user.id} is donating {amount} to category {category_id}")
                
                new_donation = Donation(amount=amount, user_id=current_user.id, category_id=category_id)
                db.session.add(new_donation)
                db.session.commit()
                
                flash('Thank you for your donation!', 'success')
                return redirect(url_for('profile'))
            except Exception as e:
                # Log the error
                app.logger.error(f"Error occurred while processing donation: {e}")
                
                # Rollback the transaction in case of an error
                db.session.rollback()
                
                flash('An error occurred while processing your donation. Please try again.', 'danger')
        else:
            flash('Please enter a valid amount.', 'danger')
    
    return render_template('donation_detail.html', category=category)




@app.route('/donation/<int:category_id>/make_donation', methods=['POST'])
@login_required
def make_donation(category_id):
    amount = request.form.get('amount')
    if amount:
        new_donation = Donation(amount=amount, user_id=current_user.id, category_id=category_id)
        db.session.add(new_donation)
        db.session.commit()
        flash('Thank you for your donation!', 'success')
        return redirect(url_for('profile'))
    else:
        flash('Please enter a valid amount.', 'danger')
        return redirect(url_for('donation_detail', category_id=category_id))

@app.route('/donate_to_aid_request/<int:aid_request_id>', methods=['POST'])
@login_required
def donate_to_aid_request(aid_request_id):
    amount = request.form.get('amount')

    if amount and float(amount) > 0:
        try:
            # Create a new donation record linked to the aid request
            new_donation = Donation(amount=float(amount), user_id=current_user.id, aid_request_id=aid_request_id)
            db.session.add(new_donation)

            # Update the current_amount in the HelpRequest table
            aid_request = HelpRequest.query.get(aid_request_id)
            if aid_request:
                aid_request.current_amount += float(amount)
                db.session.commit()

                flash('Thank you for your donation!', 'success')
            else:
                flash('Aid request not found.', 'danger')

        except Exception as e:
            # Log the error
            current_app.logger.error(f"Error occurred while processing donation: {e}")
            db.session.rollback()
            flash('An error occurred while processing your donation. Please try again.', 'danger')
    else:
        flash('Please enter a valid donation amount.', 'danger')

    return redirect(url_for('donation'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

from flask import jsonify, session

@app.route('/volunteer', methods=['GET', 'POST'])
@login_required
def volunteer():
    # Check if a volunteer report already exists for this user
    existing_report = VolunteerReport.query.filter_by(user_id=current_user.id).first()
    if existing_report:
        return redirect(url_for('volunteer_opportunities'))

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        age = request.form.get('age')
        location = request.form.get('location')
        skills_interests = request.form.get('skills_interests')

        new_report = VolunteerReport(
            user_id=current_user.id,
            full_name=full_name,
            email=email,
            phone_number=phone_number,
            age=age,
            location=location,
            skills_interests=skills_interests
        )
        try:
            db.session.add(new_report)
            db.session.commit()
            session['volunteer_report_id'] = new_report.id  # Store the report ID in the session
            return jsonify({'success': True, 'message': 'Your volunteer information has been submitted.'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': f'Error: {str(e)}'})
    
    volunteer_image = fetch_unsplash_image('volunteer')
    community_image = fetch_unsplash_image('community')
    helping_image = fetch_unsplash_image('helping')
    return render_template('volunteer.html', volunteer_image=volunteer_image, community_image=community_image, helping_image=helping_image)


@app.route('/volunteer/loading')
def volunteer_loading():
    if 'volunteer_report_id' not in session:
        return redirect(url_for('volunteer'))

    # Render a loading page
    return render_template('volunteer_loading.html')

@app.route('/volunteer/opportunities')
@login_required
def volunteer_opportunities():
    report = VolunteerReport.query.filter_by(user_id=current_user.id).first()
    if not report:
        flash('Please submit your volunteer information first.', 'danger')
        return redirect(url_for('volunteer'))

    # Get all the opportunities the user has already signed up for
    signed_up_opportunity_ids = [signup.opportunity_id for signup in VolunteerSignup.query.filter_by(user_id=current_user.id).all()]
    
    # Get all opportunities that match the user's skills but exclude the ones they've already signed up for
    matched_opportunities = [opportunity for opportunity in match_opportunities(report.skills_interests) if opportunity.id not in signed_up_opportunity_ids]
    
    return render_template('volunteer_opportunities.html', opportunities=matched_opportunities)


@app.route('/get_skills', methods=['GET'])
def get_skills():
    opportunities = VolunteerOpportunity.query.all()
    skills_set = set()
    for opportunity in opportunities:
        skills = opportunity.skills_keywords.split(', ')
        for skill in skills:
            skills_set.add(skill.strip())
    skills_list = sorted(list(skills_set))
    return jsonify(skills_list)

from flask import jsonify

@app.route('/volunteer_signup/<int:opportunity_id>', methods=['POST'])
@login_required
def volunteer_signup(opportunity_id):
    opportunity = VolunteerOpportunity.query.get_or_404(opportunity_id)

    # Check if the user has already submitted a volunteer report
    report = VolunteerReport.query.filter_by(user_id=current_user.id).first()
    if not report:
        return jsonify({'success': False, 'message': 'Please submit your volunteer information first.'}), 400

    # Check if the user has already signed up for this opportunity
    duplicate_signup = VolunteerSignup.query.filter_by(user_id=current_user.id, opportunity_id=opportunity_id).first()
    if duplicate_signup:
        return jsonify({'success': False, 'message': 'You have already signed up for this opportunity.'}), 400

    new_signup = VolunteerSignup(
        user_id=current_user.id,
        opportunity_id=opportunity_id,
        report_id=report.id
    )
    db.session.add(new_signup)
    db.session.commit()
    return jsonify({'success': True})



@app.route('/cancel_report/<int:report_id>', methods=['POST'])
@login_required
def cancel_report(report_id):
    report = VolunteerReport.query.get_or_404(report_id)

    if report.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    db.session.delete(report)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Report canceled successfully'})


@app.route('/delete_report/<int:report_id>', methods=['DELETE'])
@login_required
def delete_report(report_id):
    report = VolunteerReport.query.get_or_404(report_id)

    if report.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    # Delete associated signups
    signups = VolunteerSignup.query.filter_by(report_id=report.id).all()
    for signup in signups:
        db.session.delete(signup)

    db.session.delete(report)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Report and associated opportunities deleted successfully'})

@app.route('/report_volunteer_hours/<int:opportunity_id>', methods=['POST'])
@login_required
def report_volunteer_hours(opportunity_id):
    try:
        hours_worked = float(request.form.get('hours_worked'))
        description = request.form.get('description')
        user_id = current_user.id

        new_hours = VolunteerHours(
            user_id=user_id,
            opportunity_id=opportunity_id,
            hours_worked=hours_worked,
            description=description
        )

        db.session.add(new_hours)
        db.session.commit()

        flash('Hours reported successfully! Pending verification.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error reporting hours: {e}', 'danger')

    return redirect(url_for('profile'))

# routes.py

@app.route('/add_credit_card', methods=['GET', 'POST'])
@login_required
def add_credit_card():
    if request.method == 'POST':
        card_number = request.form.get('card_number')
        expiration_date = request.form.get('expiration_date')
        cvv = request.form.get('cvv')
        cardholder_name = request.form.get('cardholder_name')

        # Example: Storing the last four digits
        last_four_digits = card_number[-4:]

        # Add logic to process and store the credit card information securely
        # Store only non-sensitive information
        new_card = CreditCard(
            user_id=current_user.id,
            cardholder_name=cardholder_name,
            last_four_digits=last_four_digits,
            expiration_date=expiration_date
        )
        db.session.add(new_card)
        db.session.commit()

        current_user.has_credit_card = True
        db.session.commit()

        flash('Credit card added successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('add_credit_card.html')
