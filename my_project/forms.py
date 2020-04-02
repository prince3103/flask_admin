from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, EqualTo, Email

class LoginForm(FlaskForm):
	# github_submit = SubmitField('Log In With Github')
	email = StringField('Email*', validators = [DataRequired(), Email()])
	password = PasswordField('Password*', validators = [DataRequired()])
	validate_error = StringField("")
	remember_me = BooleanField('Remember Me')
	submit = SubmitField('Log In')

class RegisterForm(FlaskForm):
	email = StringField('Email*', validators = [DataRequired(), Email()])		#unique in database model
	username = StringField('Username*', validators = [DataRequired()])	#unique in database model
	password = PasswordField('Password*', validators = [DataRequired(), EqualTo('confirm_password', message='Passwords must match')])		#match with confirm password
	confirm_password = PasswordField('Confirm Password*', validators = [DataRequired()])
	validate_error = StringField("")
	submit = SubmitField('Register')



class ForgotPassword1(FlaskForm):
	email = StringField('Email*', validators = [DataRequired(), Email()])	
	validate_error = StringField("")
	submit = SubmitField('Submit')


class ForgotPassword2(FlaskForm):
	password = PasswordField('Password*', validators = [DataRequired(), EqualTo('confirm_password', message='Passwords must match')])		#match with confirm password
	confirm_password = PasswordField('Confirm Password*', validators = [DataRequired()])
	validate_error = StringField("")
	submit = SubmitField('Submit')