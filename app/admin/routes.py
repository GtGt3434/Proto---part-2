from flask import render_template, redirect, url_for, flash, request
from flask_login import current_user
from functools import wraps
from . import admin_bp
from .. import db
from ..models import User, DonationCategory, VolunteerOpportunity, HelpRequest

# Admin access decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            return redirect(url_for('index'))  # Redirect to homepage if not admin
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/')
@admin_required
def admin_dashboard():
    return render_template('admin/dashboard.html')

@admin_bp.route('/donation_categories')
@admin_required
def admin_donation_categories():
    categories = DonationCategory.query.all()
    return render_template('admin/donation_categories.html', categories=categories)

@admin_bp.route('/donation_categories/new', methods=['GET', 'POST'])
@admin_required
def admin_new_donation_category():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        image_keyword = request.form.get('image_keyword')
        learn_more_url = request.form.get('learn_more_url')
        
        new_category = DonationCategory(
            title=title,
            description=description,
            image_keyword=image_keyword,
            learn_more_url=learn_more_url
        )
        db.session.add(new_category)
        db.session.commit()
        flash('Donation category created successfully!', 'success')
        return redirect(url_for('admin.admin_donation_categories'))
    return render_template('admin/new_donation_category.html')

@admin_bp.route('/donation_categories/edit/<int:category_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_donation_category(category_id):
    category = DonationCategory.query.get_or_404(category_id)
    if request.method == 'POST':
        category.title = request.form.get('title')
        category.description = request.form.get('description')
        category.image_keyword = request.form.get('image_keyword')
        category.learn_more_url = request.form.get('learn_more_url')
        db.session.commit()
        flash('Donation category updated successfully!', 'success')
        return redirect(url_for('admin.admin_donation_categories'))
    return render_template('admin/edit_donation_category.html', category=category)

@admin_bp.route('/donation_categories/delete/<int:category_id>', methods=['POST'])
@admin_required
def admin_delete_donation_category(category_id):
    category = DonationCategory.query.get_or_404(category_id)

    # Delete related donations first
    for donation in category.donations:
        db.session.delete(donation)
    db.session.delete(category)
    db.session.commit()
    flash('Donation category and related donations deleted successfully!', 'success')
    return redirect(url_for('admin.admin_donation_categories'))


@admin_bp.route('/volunteer_opportunities')
@admin_required
def admin_volunteer_opportunities():
    opportunities = VolunteerOpportunity.query.all()
    return render_template('admin/volunteer_opportunities.html', opportunities=opportunities)

@admin_bp.route('/volunteer_opportunities/new', methods=['GET', 'POST'])
@admin_required
def admin_new_volunteer_opportunity():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        location = request.form.get('location')
        skills_keywords = request.form.get('skills_keywords')
        image_url = request.form.get('image_url')
        
        new_opportunity = VolunteerOpportunity(
            name=name,
            description=description,
            location=location,
            skills_keywords=skills_keywords,
            image_url=image_url
        )
        db.session.add(new_opportunity)
        db.session.commit()
        flash('Volunteer opportunity created successfully!', 'success')
        return redirect(url_for('admin.admin_volunteer_opportunities'))
    return render_template('admin/new_volunteer_opportunity.html')

@admin_bp.route('/volunteer_opportunities/edit/<int:opportunity_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_volunteer_opportunity(opportunity_id):
    opportunity = VolunteerOpportunity.query.get_or_404(opportunity_id)
    if request.method == 'POST':
        opportunity.name = request.form.get('name')
        opportunity.description = request.form.get('description')
        opportunity.location = request.form.get('location')
        opportunity.skills_keywords = request.form.get('skills_keywords')
        opportunity.image_url = request.form.get('image_url')
        db.session.commit()
        flash('Volunteer opportunity updated successfully!', 'success')
        return redirect(url_for('admin.admin_volunteer_opportunities'))
    return render_template('admin/edit_volunteer_opportunity.html', opportunity=opportunity)

@admin_bp.route('/volunteer_opportunities/delete/<int:opportunity_id>', methods=['POST'])
@admin_required
def admin_delete_volunteer_opportunity(opportunity_id):
    opportunity = VolunteerOpportunity.query.get_or_404(opportunity_id)

    # Delete related records first
    for signup in opportunity.volunteer_signups:
        db.session.delete(signup)
    for hours in opportunity.volunteer_hours:
        db.session.delete(hours)
    db.session.delete(opportunity)
    db.session.commit()
    flash('Volunteer opportunity and related records deleted successfully!', 'success')
    return redirect(url_for('admin.admin_volunteer_opportunities'))


@admin_bp.route('/help_requests')
@admin_required
def admin_help_requests():
    help_requests = HelpRequest.query.all()
    return render_template('admin/help_requests.html', help_requests=help_requests)

@admin_bp.route('/help_requests/approve/<int:request_id>', methods=['POST'])
@admin_required
def admin_approve_help_request(request_id):
    help_request = HelpRequest.query.get_or_404(request_id)
    help_request.evaluation_status = 'Approved'
    db.session.commit()
    flash('Help request approved.', 'success')
    return redirect(url_for('admin.admin_help_requests'))

@admin_bp.route('/help_requests/reject/<int:request_id>', methods=['POST'])
@admin_required
def admin_reject_help_request(request_id):
    help_request = HelpRequest.query.get_or_404(request_id)
    help_request.evaluation_status = 'Rejected'
    db.session.commit()
    flash('Help request rejected.', 'danger')
    return redirect(url_for('admin.admin_help_requests'))

@admin_bp.route('/users')
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.role = request.form.get('role')
        db.session.commit()
        flash('User role updated successfully.', 'success')
        return redirect(url_for('admin.admin_users'))
    return render_template('admin/edit_user.html', user=user)

@admin_bp.route('/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin.admin_users'))

    # Delete related records first
    models_to_delete = [
        user.donations,
        user.volunteer_reports,
        user.volunteer_signups,
        user.volunteer_hours,
        user.help_requests,
        user.credit_cards
    ]
    for records in models_to_delete:
        for record in records:
            db.session.delete(record)
    db.session.delete(user)
    db.session.commit()
    flash('User and related records deleted successfully!', 'success')
    return redirect(url_for('admin.admin_users'))


@admin_bp.route('/users/confirm_delete/<int:user_id>', methods=['GET'])
@admin_required
def admin_confirm_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin.admin_users'))

    # Check for related records
    related_records = {
        'Donations': user.donations,
        'Volunteer Reports': user.volunteer_reports,
        'Volunteer Signups': user.volunteer_signups,
        'Volunteer Hours': user.volunteer_hours,
        'Help Requests': user.help_requests,
        'Credit Cards': user.credit_cards
    }

    has_related_records = any(len(records) > 0 for records in related_records.values())

    return render_template('admin/confirm_delete_user.html', user=user, related_records=related_records, has_related_records=has_related_records)

@admin_bp.route('/donation_categories/confirm_delete/<int:category_id>', methods=['GET'])
@admin_required
def admin_confirm_delete_category(category_id):
    category = DonationCategory.query.get_or_404(category_id)
    related_donations = category.donations

    has_related_donations = len(related_donations) > 0

    return render_template('admin/confirm_delete_category.html', category=category, donations=related_donations, has_related_donations=has_related_donations)

@admin_bp.route('/volunteer_opportunities/confirm_delete/<int:opportunity_id>', methods=['GET'])
@admin_required
def admin_confirm_delete_opportunity(opportunity_id):
    opportunity = VolunteerOpportunity.query.get_or_404(opportunity_id)
    related_signups = opportunity.volunteer_signups
    related_hours = opportunity.volunteer_hours

    has_related_records = len(related_signups) > 0 or len(related_hours) > 0

    return render_template('admin/confirm_delete_opportunity.html', opportunity=opportunity,
                           signups=related_signups, hours=related_hours, has_related_records=has_related_records)
