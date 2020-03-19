from flask import render_template, url_for, redirect, request, flash, abort
from my_project.forms import LoginForm, RegisterForm
from my_project import app, db
from my_project.models import User, MyModelView, MyAdminIndexView
from flask_login import login_user, logout_user, login_required
from werkzeug.security import check_password_hash
from is_safe_url import is_safe_url
from flask_admin import Admin


admin = Admin(app, name='Admin', template_mode='bootstrap3', index_view = MyAdminIndexView())
admin.add_view(MyModelView(User, db.session))


@app.route("/")
def home():
	return render_template('home.html')


@app.route('/login', methods=('GET', 'POST'))
def login():
	form = LoginForm()
	
	validate_error="Validation Message"
	if form.validate_on_submit():

		email = request.form['email']
		user = User.query.filter_by(email=email).first()
		if user:
			password = check_password_hash(user.password, request.form['password'])	

			if password:
				login_user(user)
				flash('Logged in successfully.')
				next = request.args.get('next')
				#is_safe_url should check if the url is safe for redirects.
				#See http://flask.pocoo.org/snippets/62/ for an example.
				if next and not is_safe_url(next, {"example.com", "www.example.com"}):	#do I need to change this to heroku url
					return abort(400)

				return redirect(next or url_for('home'))
			else:
				validate_error="Invalid email address or password"
		else:
			validate_error="Invalid email address or password"
	elif request.method == 'POST':
		for key in form.errors.keys():
			validate_error = form.errors[key][0]
	return render_template('login.html', form = form, validate_error= validate_error)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You logged out!')
    return redirect(url_for('home'))


@app.route('/register', methods=('GET', 'POST'))
def register():
	form = RegisterForm()
	validate_error="Validation Message"
	if form.validate_on_submit():
		username = request.form['username']
		email = request.form['email']
		password = request.form['password']
		check_username = User.checkUsername(username)
		check_email = User.checkEmail(email)
		if not check_username:
			validate_error = "Sorry, that username is taken!"
		elif not check_email:
			validate_error = "Your email has been registered already!"
		else:
			user = User(username, email, password)
			db.session.add(user)
			db.session.commit()
			flash('Thanks for registering! Now you can login!')
			return redirect(url_for('login'))
	elif request.method == 'POST':
		for key in form.errors.keys():
			validate_error = form.errors[key][0]
	return render_template('register.html', form= form, validate_error= validate_error)


if __name__== '__main__':
	db.create_all()
	app.run(port = 8080, debug=True)

