from flask import Flask, render_template, url_for, redirect
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


@app.route('/')
def home():
    coasters = Coaster.query.all()
    return render_template('home.html', coasters=coasters)


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


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


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
        inserted_names = set()  # To keep track of inserted coaster names
        for row in csv_reader:
            name = row['Name'].strip()
            
            # Skip duplicates within the same CSV upload session
            if name in inserted_names:
                continue

            if Coaster.query.filter_by(name=name).first():
                continue

            # Safely convert numerical fields
            try:
                length = float(row['Length']) if row['Length'].strip() else None
                height = float(row['Height']) if row['Height'].strip() else None
                drop = float(row['Drop']) if row['Drop'].strip() else None
                speed = float(row['Speed']) if row['Speed'].strip() else None
                inversions = int(row['Inversions']) if row['Inversions'].strip() else None
                vertical_angle = float(row['Vertical Angle']) if row['Vertical Angle'].strip() else None
                duration = float(row['Duration']) if row['Duration'].strip() else None
            except ValueError as e:
                continue  # Skip to the next row if conversion fails

            try:
                coaster = Coaster(
                    name=name,
                    park=row.get('Park', None),
                    location=row.get('Location', None),
                    opening_date=row.get('Opening Date', None),
                    length=length,
                    height=height,
                    drop=drop,
                    speed=speed,
                    inversions=inversions,
                    vertical_angle=vertical_angle,
                    duration=duration,
                    rcdb_link=row.get('RCDB Link', None)
                )
                db.session.add(coaster)
                db.session.commit()
                inserted_names.add(name)
            except IntegrityError:
                db.session.rollback()
            except Exception as e:
                db.session.rollback()

if __name__ == "__main__": 
    with app.app_context(): 
        db.create_all() 
        insert_coasters_from_csv('every_operating_coaster.csv')
    app.run(debug=True)