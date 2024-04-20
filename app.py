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
from flask_wtf.csrf import CSRFProtect

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
    reviews = db.relationship('Review', backref='user', lazy=True, cascade='all, delete-orphan')

class Coaster(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    park = db.Column(db.String(255), nullable=True, default='None')
    location = db.Column(db.String(255), nullable=True, default='None')
    opening_date = db.Column(db.String(255), nullable=True, default='None')
    length = db.Column(db.String(255), nullable=True, default='None')
    height = db.Column(db.String(255), nullable=True, default='None')
    drop = db.Column(db.String(255), nullable=True, default='None')
    speed = db.Column(db.String(255), nullable=True, default='None')
    inversions = db.Column(db.String(255), nullable=True, default='None')
    vertical_angle = db.Column(db.String(255), nullable=True, default='None')
    duration = db.Column(db.String(255), nullable=True, default='None')
    rcdb_link = db.Column(db.String(255), nullable=True, default='None')
    
    __table_args__ = (db.UniqueConstraint('name', 'park', name='_name_park_uc'),)
    
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    coaster_id = db.Column(db.Integer, db.ForeignKey('coaster.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text, nullable=False)
    coaster = db.relationship('Coaster', backref=db.backref('reviews', lazy=True))
    
class FavoriteCoaster(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    coaster_id = db.Column(db.Integer, db.ForeignKey('coaster.id'), nullable=False)
    rank = db.Column(db.Integer, nullable=False)  # Rank from 1 to 10

    user = db.relationship('User', backref=db.backref('favorite_coasters', lazy='dynamic'))
    coaster = db.relationship('Coaster', backref='favorited_by')

    __table_args__ = (db.UniqueConstraint('user_id', 'rank', name='_user_rank_uc'),)

    
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
    
class ReviewForm(FlaskForm):
    rating = StringField('Rating', validators=[InputRequired()])
    content = StringField('Review', validators=[InputRequired()])
    submit = SubmitField('Submit Review')

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
            flash('Invalid username or password', 'error')

    return render_template('home.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    search_form = SearchForm()
    user_favorites = FavoriteCoaster.query.filter_by(user_id=current_user.id).order_by(FavoriteCoaster.rank).all()
    
    coasters = None
    if search_form.validate_on_submit():
        search_query = search_form.search_query.data
        coasters = Coaster.query.filter(Coaster.name.ilike(f'%{search_query}%')).all()

    user_reviews = Review.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', search_form=search_form, coasters=coasters, user_reviews=user_reviews, user_favorites=user_favorites)



@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))  

    return render_template('register.html', form=form)

@app.route('/coasters/<int:coaster_id>', methods=['GET', 'POST'])
@login_required
def coaster_details(coaster_id):
    coaster = Coaster.query.get_or_404(coaster_id)
    existing_review = Review.query.filter_by(user_id=current_user.id, coaster_id=coaster_id).first()
    review_form = ReviewForm()

    if request.method == 'POST':
        if review_form.validate_on_submit():
            if existing_review:
                print("balls")
                existing_review.rating = review_form.rating.data
                existing_review.content = review_form.content.data
                flash('Review updated successfully!', 'success')
            else:
                # Create a new review if none exists
                new_review = Review(
                    user_id=current_user.id,
                    coaster_id=coaster_id,
                    rating=review_form.rating.data,
                    content=review_form.content.data
                )
                db.session.add(new_review)
                flash('Review added successfully!', 'success')
            db.session.commit()
            return redirect(url_for('coaster_details', coaster_id=coaster_id))
        else:
            for fieldName, errorMessages in review_form.errors.items():
                for err in errorMessages:
                    flash(f"{fieldName}: {err}", 'error')

    review_form.rating.data = existing_review.rating if existing_review else None
    review_form.content.data = existing_review.content if existing_review else None

    reviews = (db.session.query(Review, User.username)
               .join(User, User.id == Review.user_id)
               .filter(Review.coaster_id == coaster_id)
               .all())

    return render_template('coaster_details.html', coaster=coaster, review_form=review_form, reviews=reviews)

@app.route('/delete_review/<int:review_id>', methods=['POST'])
@login_required
def delete_review(review_id):
    review = Review.query.get_or_404(review_id)
    
    # Ensure the current user is the owner of the review
    if review.user_id != current_user.id:
        flash('You do not have permission to delete this review.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        db.session.delete(review)
        db.session.commit()
        flash('Review deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting review.', 'error')
        print(f"Error: {e}")
    
    return redirect(url_for('dashboard'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = current_user
    db.session.delete(user)
    try:
        db.session.commit()
        flash('Your account has been successfully deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting account: {str(e)}', 'error')
    logout_user()
    return redirect(url_for('home'))

@app.route('/add_favorite/<int:coaster_id>', methods=['POST'])
@login_required
def add_favorite(coaster_id):
    current_favorites = FavoriteCoaster.query.filter_by(user_id=current_user.id).order_by(FavoriteCoaster.rank).all()
    if len(current_favorites) >= 10:
        flash('You already have 10 favorite coasters. Remove one before adding another.', 'error')
        return redirect(url_for('dashboard'))

    if any(fav.coaster_id == coaster_id for fav in current_favorites):
        flash('This coaster is already in your top 10 favorites.', 'error')
        return redirect(url_for('dashboard'))

    new_rank = len(current_favorites) + 1
    new_favorite = FavoriteCoaster(user_id=current_user.id, coaster_id=coaster_id, rank=new_rank)
    db.session.add(new_favorite)
    try:
        db.session.commit()
        flash('Coaster added to your favorites at rank #' + str(new_rank) + '!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding coaster to favorites: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))


@app.route('/remove_favorite/<int:coaster_id>', methods=['POST'])
@login_required
def remove_favorite(coaster_id):
    favorite_to_remove = FavoriteCoaster.query.filter_by(user_id=current_user.id, coaster_id=coaster_id).first()
    if not favorite_to_remove:
        flash('This coaster is not in your top 10 favorites.', 'error')
        return redirect(url_for('dashboard'))


    db.session.delete(favorite_to_remove)
    following_favorites = FavoriteCoaster.query.filter(
        FavoriteCoaster.user_id == current_user.id,
        FavoriteCoaster.rank > favorite_to_remove.rank
    ).order_by(FavoriteCoaster.rank).all()

    for favorite in following_favorites:
        favorite.rank -= 1  # Decrement ranks of all subsequent favorites

    try:
        db.session.commit()
        flash('Coaster removed from your favorites.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error removing coaster from favorites: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/reset_favorites', methods=['POST'])
@login_required
def reset_favorites():
    # Remove all favorite coasters for the current user
    try:
        FavoriteCoaster.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        flash('All your favorite coasters have been reset.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to reset favorite coasters.', 'error')
        print(f"Error: {e}")
    
    return redirect(url_for('dashboard'))

import csv
from sqlalchemy.exc import IntegrityError

import csv
from sqlalchemy.exc import IntegrityError

import csv
from sqlalchemy.exc import IntegrityError

def insert_coasters_from_csv(csv_file):
    with open(csv_file, 'r', newline='', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            # Extract and strip all necessary fields
            name = row.get('Name', 'None').strip()
            park = row.get('Park', 'None').strip()
            location = row.get('Location', 'None').strip()
            opening_date = row.get('Opening Date', 'None').strip()
            length = row.get('Length', 'None').strip()
            height = row.get('Height', 'None').strip()
            drop = row.get('Drop', 'None').strip()
            speed = row.get('Speed', 'None').strip()
            inversions = row.get('Inversions', 'None').strip()
            vertical_angle = row.get('Vertical Angle', 'None').strip()
            duration = row.get('Duration', 'None').strip()
            rcdb_link = row.get('RCDB Link', 'None').strip()

            # Check if the coaster already exists to prevent duplicates
            if Coaster.query.filter_by(name=name, park=park, location=location).first():
                print(f"Skipped duplicate entry for {name} in {park} at {location}.")
                continue  # Skip if this coaster already exists

            # Create a new coaster instance with all fields
            coaster = Coaster(
                name=name,
                park=park,
                location=location,
                opening_date=opening_date if opening_date != 'None' else None,
                length=length if length != 'None' else None,
                height=height if height != 'None' else None,
                drop=drop if drop != 'None' else None,
                speed=speed if speed != 'None' else None,
                inversions=inversions if inversions != 'None' else None,
                vertical_angle=vertical_angle if vertical_angle != 'None' else None,
                duration=duration if duration != 'None' else None,
                rcdb_link=rcdb_link if rcdb_link != 'None' else None
            )

            try:
                db.session.add(coaster)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                print(f"Integrity error occurred while inserting {name} at {park} in {location}.")
            except Exception as e:
                db.session.rollback()
                print(f"Failed to insert {name} at {park} in {location}: {e}")

if __name__ == "__main__": 
    with app.app_context(): 
        db.create_all() 
        #insert_coasters_from_csv('every_operating_coaster.csv')
    app.run(debug=True)