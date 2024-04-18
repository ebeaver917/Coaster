from flask import *
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import csv
from datetime import datetime
from sqlalchemy.exc import IntegrityError


app = Flask(__name__)

bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/ebeav/OneDrive/Desktop/Coaster/database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class Coaster(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    park = db.Column(db.String(100))
    location = db.Column(db.String(100))
    opening_date = db.Column(db.String(20))
    length = db.Column(db.Float)
    height = db.Column(db.Float)
    drop = db.Column(db.Float)
    speed = db.Column(db.Float)
    inversions = db.Column(db.Integer)
    vertical_angle = db.Column(db.Float)
    duration = db.Column(db.Float)
    rcdb_link = db.Column(db.String(200))
    

class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

class SearchForm(FlaskForm):
    search_query = StringField('Search', validators=[InputRequired()])
    submit = SubmitField('Search')

@app.route('/', methods=['GET', 'POST'])
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')  # Assuming you have flash messaging set up

    return render_template('home.html', form=form)


'''
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)
'''

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    search_form = SearchForm() 
    coasters = None  
    if search_form.validate_on_submit():
        search_query = search_form.search_query.data
        coasters = Coaster.query.filter(Coaster.name.ilike(f'%{search_query}%')).all()
    
    return render_template('dashboard.html', search_form=search_form, coasters=coasters)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


def insert_coasters_from_csv(csv_file):
    with open(csv_file, 'r', newline='', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)
        id=0
        for row in csv_reader:
            name = row['Name'].strip()
            park = row.get('Park', '').strip()
            location = row.get('Location', '').strip()

            # Check if the coaster already exists based on name, park, and location
            if Coaster.query.filter_by(name=name, park=park, location=location).first():
                continue  # Skip this entry if it already exists

            # Safely convert numerical fields
            try:
                length = float(row['Length']) if row['Length'].strip() else None
                height = float(row['Height']) if row['Height'].strip() else None
                drop = float(row['Drop']) if row['Drop'].strip() else None
                speed = float(row['Speed']) if row['Speed'].strip() else None
                inversions = int(row['Inversions']) if row['Inversions'].strip() else None
                vertical_angle = float(row['Vertical Angle']) if row['Vertical Angle'].strip() else None
                duration = float(row['Duration']) if row['Duration'].strip() else None
            except ValueError:
                length = None
                height = None
                drop = None
                speed = None
                inversions = None
                vertical_angle = None
                duration = None

            # Create the coaster instance
            coaster = Coaster(
                id=id,
                name=name,
                park=park,
                location=location,
                opening_date=row.get('Opening Date', '').strip() or None,
                length=length,
                height=height,
                drop=drop,
                speed=speed,
                inversions=inversions,
                vertical_angle=vertical_angle,
                duration=duration,
                rcdb_link=row.get('RCDB Link', '').strip() or None
            )
            id += 1
            # Attempt to add to the database
            try:
                db.session.add(coaster)
                db.session.commit()
            except IntegrityError:
                # Roll back if there's a database error (e.g., duplicate entry)
                db.session.rollback()
            except Exception as e:
                # Log other exceptions and roll back
                print(f"Failed to insert {name} at {park} in {location}: {e}")
                db.session.rollback()


if __name__ == "__main__": 
    with app.app_context(): 
        db.create_all() 
        insert_coasters_from_csv('every_operating_coaster.csv')
    app.run(debug=True)