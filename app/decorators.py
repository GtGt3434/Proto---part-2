from functools import wraps
from flask import redirect, url_for, flash
from flask_login import current_user

def role_required(role, message):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_authenticated and current_user.role == role:
                return f(*args, **kwargs)
            else:
                flash(message, "error")
                return redirect(url_for('login'))
        return decorated_function
    return decorator
