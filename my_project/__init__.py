import os, stripe
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer
from flask_dance.contrib.github import make_github_blueprint


secret_key = os.urandom(32)
file_path = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+ os.path.join(file_path, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
# Tell users what view to go to when they need to login.
login_manager.login_view = "login"

# set optional bootswatch theme
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'

#---for flask-mail functionlity------
app.config.from_pyfile('config.cfg')
mail = Mail(app)
url_safe_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

#-------for flask oauth functionality----------------
github_blueprint = make_github_blueprint(
    client_id="777442adcfc656de0134",
    client_secret="3d425e90bc9015bf55bab29987226148f85159d1",
)

#----Stripe for payment-------------
public_key = 'pk_test_6pRNASCoBOKtIshFeQd4XMUh'
stripe.api_key = "sk_test_BQokikJOvBiI2HlWgH4olfQ2"