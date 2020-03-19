from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Email

class LoginForm(FlaskForm):
	email = StringField('Email:', validators = [DataRequired(), Email()])
	password = PasswordField('Password:', validators = [DataRequired()])
	validate_error = StringField()
	submit = SubmitField('LogIn')

class RegisterForm(FlaskForm):
	email = StringField('Email:', validators = [DataRequired(), Email()])		#unique in database model
	username = StringField('Username:', validators = [DataRequired()])	#unique in database model
	password = PasswordField('Password:', validators = [DataRequired(), EqualTo('confirm_password', message='Passwords must match')])		#match with confirm password
	confirm_password = PasswordField('Confirm Password:', validators = [DataRequired()])
	validate_error = StringField()
	submit = SubmitField('Register')