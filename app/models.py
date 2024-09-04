from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import UserMixin
from sqlalchemy.dialects.mysql import MEDIUMTEXT

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)  # Updated to 512
    role = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    has_credit_card = db.Column(db.Boolean, nullable=False, default=False)  


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Donation(db.Model):
    __tablename__ = 'donations'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    category_id = db.Column(db.Integer, db.ForeignKey('donation_categories.id'), nullable=True)
    aid_request_id = db.Column(db.Integer, db.ForeignKey('help_requests.id'), nullable=True)  # New field
    amount = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('donations', lazy=True))
    category = db.relationship('DonationCategory', backref=db.backref('donations', lazy=True))
    aid_request = db.relationship('HelpRequest', backref=db.backref('donations', lazy=True))  # New relationship




class DonationCategory(db.Model):
    __tablename__ = 'donation_categories'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(300), nullable=False)
    image_keyword = db.Column(db.String(100), nullable=False)
    learn_more_url = db.Column(db.String(300), nullable=False)

class Volunteer(db.Model):
    __tablename__ = 'volunteers'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    skills_interests = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class VolunteerOpportunity(db.Model):
    __tablename__ = 'volunteer_opportunities'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    skills_keywords = db.Column(db.String(255), nullable=False)
    image_url = db.Column(db.String(255), nullable=True)  # New column for image URL
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<VolunteerOpportunity {self.name}>'



class VolunteerReport(db.Model):
    __tablename__ = 'volunteer_reports'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20))
    age = db.Column(db.Integer)
    location = db.Column(db.String(100))
    skills_interests = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('volunteer_reports', lazy=True))

    def __repr__(self):
        return f'<VolunteerReport {self.full_name}>'

class VolunteerSignup(db.Model):
    __tablename__ = 'volunteer_signups'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    opportunity_id = db.Column(db.Integer, db.ForeignKey('volunteer_opportunities.id'))
    report_id = db.Column(db.Integer, db.ForeignKey('volunteer_reports.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('volunteer_signups', lazy=True))
    opportunity = db.relationship('VolunteerOpportunity', backref=db.backref('volunteer_signups', lazy=True))
    report = db.relationship('VolunteerReport', backref=db.backref('volunteer_signups', lazy=True))

    def __repr__(self):
        return f'<VolunteerSignup {self.id}>'
    
class VolunteerHours(db.Model):
    __tablename__ = 'volunteer_hours'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    opportunity_id = db.Column(db.Integer, db.ForeignKey('volunteer_opportunities.id'), nullable=False)
    hours_worked = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    verified = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('volunteer_hours', lazy=True))
    opportunity = db.relationship('VolunteerOpportunity', backref=db.backref('volunteer_hours', lazy=True))

    def __repr__(self):
        return f'<VolunteerHours {self.id}>'



class HelpRequest(db.Model):
    __tablename__ = 'help_requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    full_name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    contact_number = db.Column(db.String(20), nullable=False)
    assistance_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(300), nullable=False)
    income = db.Column(db.Float, nullable=False)
    expenses = db.Column(db.Float, nullable=False)
    assistance_amount = db.Column(db.Float, nullable=False)
    current_amount = db.Column(db.Float, nullable=False, default=0.0)  
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # New fields for tracking status and evaluation
    evaluation_status = db.Column(db.String(50), nullable=False, default='Pending')
    evaluation_notes = db.Column(MEDIUMTEXT, nullable=True)
    document_paths = db.Column(db.Text, nullable=True)  # Store file paths as comma-separated values
    summary = db.Column(MEDIUMTEXT, nullable=True)  

    user = db.relationship('User', backref=db.backref('help_requests', lazy=True))

    def __repr__(self):
        return f'<HelpRequest {self.id} - {self.evaluation_status}>'

class CreditCard(db.Model):
    __tablename__ = 'credit_cards'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    cardholder_name = db.Column(db.String(100), nullable=False)
    last_four_digits = db.Column(db.String(4), nullable=False)  # Store only the last 4 digits of the card number
    expiration_date = db.Column(db.String(7), nullable=False)  # Format: MM/YYYY
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('credit_cards', lazy=True))

    def __repr__(self):
        return f'<CreditCard {self.id} - {self.last_four_digits}>'


