from app import app, db
from app.models import DonationCategory
from flask import url_for

def update_categories():
    with app.app_context():
        categories = DonationCategory.query.all()
        for category in categories:
            category.learn_more_url = url_for('donation_detail', category_id=category.id, _external=True)
            db.session.add(category)
        db.session.commit()
        print("Categories updated successfully!")


