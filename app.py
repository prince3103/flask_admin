from flask import render_template, url_for, redirect, request, flash, abort
from my_project.forms import (LoginForm, RegisterForm,
 ForgotPassword1, ForgotPassword2)
from my_project import (app, db, url_safe_serializer,
 mail, github_blueprint, public_key, stripe)
from my_project.models import (User, MyModelView,
 MyAdminIndexView, LogoutMenuLink)
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from is_safe_url import is_safe_url
from flask_admin import Admin
from flask_mail import Message
from itsdangerous import SignatureExpired
from flask_dance.contrib.github import github

admin = Admin(app, name='Admin', template_mode='bootstrap3', index_view = MyAdminIndexView())
admin.add_view(MyModelView(User, db.session))

# admin.add_link(LoginMenuLink(name='Login', category='', url="/login"))
admin.add_link(LogoutMenuLink(name='Logout', category='', url="/admin_logout"))

#for flask oauth----------------
app.register_blueprint(github_blueprint, url_prefix="/github_login")

@app.route("/github")
def github_login():
	if not github.authorized:
		return redirect(url_for('github.login'))
	account_info = github.get('/user')
	if account_info.ok:
		account_info_json = account_info.json()
		username = "github_"+account_info_json['login']
		email = "thirdparty@github.com"
		password = "thirdparty"

		check_username = User.checkUsername(username)
		if check_username:
			user = User(username, email, password)
			try:
				db.session.add(user)
				db.session.commit()

				
			except:
				return "<h1>Request Failed</h1>"
		else:
			user = User.query.filter_by(username=username).first()
		login_user(user, remember=False)
		flash('Logged in successfully.')
		next = request.args.get('next')
		#is_safe_url should check if the url is safe for redirects.
		#See http://flask.pocoo.org/snippets/62/ for an example.
		if next and not is_safe_url(next, {"example.com", "www.example.com"}):	#do I need to change this to heroku url
			return abort(400)

		return redirect(url_for('home'))
	return "<h1>Request Failed</h1>"


# @app.route("/")
# @login_required
# def home():
# 	return render_template('home.html')

@app.route('/')
@login_required
def home():
    return render_template('index.html', public_key=public_key)

@app.route('/thankyou')
@login_required
def thankyou():
    return render_template('thankyou.html')

@app.route('/payment', methods=['POST'])
@login_required
def payment():

    # CUSTOMER INFORMATION
    customer = stripe.Customer.create(email=request.form['stripeEmail'],
                                      source=request.form['stripeToken'])

    # CHARGE/PAYMENT INFORMATION
    charge = stripe.Charge.create(
        customer=customer.id,
        amount=1999,
        currency='usd',
        description='Donation'
    )
    print(customer)
    print(charge)
    return redirect(url_for('thankyou'))

@app.route('/admin_login', methods=('GET', 'POST'))
def admin_login():
	if current_user.is_authenticated:
		return redirect(url_for('admin_logout'))
	form = LoginForm()
	validate_error="Fields marked with * are mandatory"
	if form.validate_on_submit():

		email = request.form['email']
		try:
			remember_me = request.form['remember_me']
		except:
			remember_me = "False"
		user = User.query.filter_by(email=email).first()
		if user and user.role=='admin':
			password = check_password_hash(user.password, request.form['password'])	

			if password:
				if remember_me:
					login_user(user, remember=True)
				else:
					login_user(user, remember=False)
				flash('Logged in successfully.')
				
				return redirect("/admin")
			else:
				validate_error="Invalid email address or password"
		else:
			validate_error="Invalid email address or password"
	elif request.method == 'POST':
		validate_error=""
		for key in form.errors.keys():
			validate_error += form.errors[key][0]
	return render_template('login.html', form = form, validate_error= validate_error)


@app.route("/admin_logout")
@login_required
def admin_logout():
	print("admin_logout")
	logout_user()
	flash('You logged out!')
	return redirect(url_for('admin_login'))


@app.route('/login', methods=('GET', 'POST'))
def login():
	if current_user.is_authenticated:
		return redirect(url_for('logout'))
	form = LoginForm()
	
	validate_error="Fields marked with * are mandatory"
	if form.validate_on_submit():

		email = request.form['email']
		# print(request.form['confirm'])
		try:
			remember_me = request.form['remember_me']
		except:
			remember_me = "False"
		user = User.query.filter_by(email=email).first()
		if user:
			if user.confirm:
				password = check_password_hash(user.password, request.form['password'])	

				if password:
					if remember_me:
						login_user(user, remember=True)
					else:
						login_user(user, remember=False)
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
				validate_error="Please confirm your email from the link povided in the mail sent to your email address"
		else:
			validate_error="Invalid email address or password"
	elif request.method == 'POST':
		validate_error=""
		for key in form.errors.keys():
			validate_error += form.errors[key][0]
	print(request.method)
	return render_template('login.html', form = form, validate_error= validate_error)


@app.route("/logout")
@login_required
def logout():
	print("user_logout")
	logout_user()
	flash('You logged out!')
	return redirect(url_for('login'))


@app.route('/register', methods=('GET', 'POST'))
def register():
	boolean_registered = False
	form = RegisterForm()
	validate_error="Fields marked with * are mandatory"
	if form.validate_on_submit():
		username = request.form['username']
		email = request.form['email']
		password = request.form['password']
		check_email = User.checkEmail(email)
		check_username = User.checkUsername(username)
		if not (check_username or check_email):
			validate_error = "Sorry, Your email has been registered already, username is taken!"
		elif not check_username:
			validate_error = "Sorry, that username is taken!"
		elif not check_email:
			validate_error = "Your email has been registered already!"
		else:
			#email confirmation code-----------------------
			token = url_safe_serializer.dumps(email, salt='email-confirm')
			msg = Message('Confirm Email', sender=app.config.get("MAIL_USERNAME"), recipients=[email])
			link = url_for('confirm_email', token=token, _external=True)
			msg.body = 'Click link to confirm: {}'.format(link)
			mail.send(msg)
			#unconfirmed user added to database
			user = User(username, email, password)
			try:
				db.session.add(user)
				db.session.commit()
				flash('Thanks for registering! Now you can login!')
				boolean_registered = True
				# return redirect(url_for('login'))
			except:
				validation_error = "Unable to register. Please try again."
	elif request.method == 'POST':
		validate_error=""
		for key in form.errors.keys():
			validate_error += form.errors[key][0]
	return render_template('register.html', form= form, validate_error= validate_error, boolean_registered=boolean_registered)


@app.route('/confirm_email/<token>')
def confirm_email(token):
	try:
		email = url_safe_serializer.loads(token, salt='email-confirm', max_age=3600)
		user = User.query.filter_by(email=email).first()
		user.confirm = True
		db.session.commit()
	except SignatureExpired:
		return '<h1>The token is expired! Please register again. <a href="/register">Click to Register</a></h1>'
	return '<h1>Thanks for confirmation. <a href="/login">Click to Log In</a></h1>'


@app.route('/forgot_password1', methods=('GET', 'POST'))
def forgot_password1():
	form = ForgotPassword1()
	validate_error="Fields Marked with * are mandatory"
	if form.validate_on_submit():
		email = request.form['email']
		if User.query.filter_by(email=email).first():
			token = url_safe_serializer.dumps(email, salt='forgot-password')
			msg = Message('Change Password', sender=app.config.get("MAIL_USERNAME"), recipients=[email])
			link = url_for('forgot_password2', token=token, _external=True)
			msg.body = 'Click link to update password: {}'.format(link)
			mail.send(msg)
			return '<h1>An email has been sent to your registered email id. Open to reset Password.</h1>'
		else:
			validate_error="Email Address not registered."
	elif request.method == 'POST':
		validate_error=""
		for key in form.errors.keys():
			validate_error += form.errors[key][0]

	return render_template('forgot_password1.html', form= form, validate_error = validate_error)	

@app.route('/forgot_password2/<token>', methods=('GET', 'POST'))
def forgot_password2(token):
	try:
		email = url_safe_serializer.loads(token, salt='forgot-password', max_age=3600)
	except SignatureExpired:
		return '<h1>The token is expired!. <a href="/forgot_password1">Click to Reset Password</a></h1></h1>'
	form = ForgotPassword2()
	validate_error="Fields Marked with * are mandatory"
	if form.validate_on_submit():
		password = request.form['password']
		confirm_password = request.form['confirm_password']
		if password == confirm_password:
			user = User.query.filter_by(email=email).first()
			try:
				user.password = password
				db.session.commit()
				return '<h1>You have successfully reset your password. <a href="/login">Click to Log In</a></h1>'
			except:
				return '<h1>Password not reset. Please try again. <a href="/forgot_password1">Click to Reset Password</a></h1>'
	elif request.method == 'POST':
		validate_error=""
		for key in form.errors.keys():
			validate_error += form.errors[key][0]
	return render_template('forgot_password2.html', form= form, validate_error= validate_error)


if __name__== '__main__':
	# db.create_all()
	app.run(port = 8080, debug=True)

