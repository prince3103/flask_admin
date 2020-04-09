from flask import url_for, redirect
from flask_login import UserMixin, current_user, fresh_login_required
from my_project import login_manager, db
from sqlalchemy import event
from werkzeug.security import generate_password_hash
from flask_admin.contrib.sqla import ModelView
from flask_admin import AdminIndexView
from flask_admin.menu import MenuLink


# The user_loader decorator allows flask-login to load the current user
# and grab their id.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class User(db.Model, UserMixin):
	__tablename__ = "Users"
	_id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80), unique=True, nullable=False, index=True)
	email = db.Column(db.String(120), nullable=False, index=True)
	password = db.Column(db.String(120), nullable = False)
	role = db.Column(db.String(120), nullable = False)
	confirm = db.Column(db.Boolean(),nullable = False, default = False)

	def __init__(self, username, email, password):
		self.username=username
		self.email=email
		self.password = password
		self.confirm=False
		
		if User.query.all()==[]:
			self.role = 'admin'
		else:
			self.role ='user'


	def get_id(self):
	    return self._id


	def __repr__(self):
		return '<User %r>' % self.username


	def checkUsername(username):
		
		if User.query.filter_by(username=username).first():
			return False
		if len(username)>6:
			if username[0:7]=="github_":	#github_ is set as prefix for github login
				return False
		return True


	def checkEmail(email):
		user = User.query.filter_by(email=email).first()
		if user:
			if user.confirm:
				return False
			else:
				try:
					db.session.delete(user)
					db.session.commit()
				except:
					return False
		return True

	

@event.listens_for(User.password, 'set', retval=True)
def hash_user_password(target, value, oldvalue, initiator):
    if value != oldvalue:
        return generate_password_hash(value)
    return value


@fresh_login_required
def fresh_login():
	print("fresh login")


class MyModelView(ModelView):
	def is_accessible(self):
		if current_user.is_authenticated:
			# fresh_login()
			return current_user.role=='admin'
		else: 
			return False
	def inaccessible_callback(self, name, **kwargs):
		return redirect(url_for('admin_login'))


class MyAdminIndexView(AdminIndexView):
	
	def is_accessible(self):
		if current_user.is_authenticated:
			return current_user.role=='admin'
		else: 
			return False
	def inaccessible_callback(self, name, **kwargs):
		return redirect(url_for('admin_login'))

# class LoginMenuLink(MenuLink):

#     def is_accessible(self):
#         return not current_user.is_authenticated 


class LogoutMenuLink(MenuLink):

    def is_accessible(self):
        return current_user.is_authenticated  