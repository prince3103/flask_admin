from flask import url_for, redirect
from flask_login import UserMixin, current_user
from my_project import login_manager, db
from sqlalchemy import event
from werkzeug.security import generate_password_hash
from flask_admin.contrib.sqla import ModelView
from flask_admin import AdminIndexView

# The user_loader decorator allows flask-login to load the current user
# and grab their id.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class User(db.Model, UserMixin):
	__tablename__ = "Users"

	_id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80), unique=True, nullable=False, index=True)
	email = db.Column(db.String(120), unique=True, nullable=False, index=True)
	password = db.Column(db.String(120), nullable = False)

	def __init__(self, username, email, password):
		self.username=username
		self.email=email
		self.password = password


	def get_id(self):
	    """Return the email address to satisfy Flask-Login's requirements."""
	    return self._id


	def __repr__(self):
		return '<User %r>' % self.username


	def checkUsername(username):
		if User.query.filter_by(username=username).first():
			return False
		return True


	def checkEmail(email):
		if User.query.filter_by(email=email).first():
			return False
		return True

@event.listens_for(User.password, 'set', retval=True)
def hash_user_password(target, value, oldvalue, initiator):
    if value != oldvalue:
        return generate_password_hash(value)
    return value

class MyModelView(ModelView):
	def is_accessible(self):
		return current_user.is_authenticated


	def inaccessible_callback(self, name, **kwargs):
		return redirect(url_for('login'))


class MyAdminIndexView(AdminIndexView):
	def is_accessible(self):
		return current_user.is_authenticated


	def inaccessible_callback(self, name, **kwargs):
		return redirect(url_for('login'))