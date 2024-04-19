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
    
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    coaster_id = db.Column(db.Integer, db.ForeignKey('coaster.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False) 
    content = db.Column(db.Text, nullable=False)

    user = db.relationship('User', backref=db.backref('reviews', lazy=True))
    coaster = db.relationship('Coaster', backref=db.backref('reviews', lazy=True))
    
class TopTenFavorite(db.Model):
    __tablename__ = 'top_ten_favorites'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    coaster_id = db.Column(db.Integer, db.ForeignKey('coaster.id'), nullable=False)
    rank = db.Column(db.Integer, nullable=False) 

    user = db.relationship('User', backref='top_ten_favorites')
    coaster = db.relationship('Coaster', backref='top_ten_favorites')

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
    coasters = None  
    all_coasters = Coaster.query.all()  # Fetch all coasters to fill the dropdowns

    if search_form.validate_on_submit():
        search_query = search_form.search_query.data
        coasters = Coaster.query.filter(Coaster.name.ilike(f'%{search_query}%')).all()

    user_top_ten = TopTenFavorite.query.filter_by(user_id=current_user.id).order_by(TopTenFavorite.rank.asc()).all()
    user_reviews = Review.query.filter_by(user_id=current_user.id).all()

    return render_template(
        'dashboard.html', 
        search_form=search_form, 
        coasters=coasters, 
        user_reviews=user_reviews, 
        user_top_ten=user_top_ten, 
        all_coasters=all_coasters  # Pass all coasters to the template
    )


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

@app.route('/review', methods=['GET', 'POST'])
@login_required
def review():
    search_form = SearchForm()
    review_form = ReviewForm()
    coasters = None

    if search_form.validate_on_submit():
        search_query = search_form.search_query.data
        coasters = Coaster.query.filter(Coaster.name.ilike(f'%{search_query}%')).all()
    
    if 'submit_review' in request.form and review_form.validate_on_submit():
        coaster_id = request.form.get('coaster_select')
        if coaster_id:
            new_review = Review(
                user_id=current_user.id,
                coaster_id=coaster_id,
                rating=review_form.rating.data,
                content=review_form.content.data
            )
            db.session.add(new_review)
            db.session.commit()
            flash('Review added successfully!')
            return redirect(url_for('dashboard'))

    return render_template('review.html', search_form=search_form, review_form=review_form, coasters=coasters)

@app.route('/coasters/<int:coaster_id>', methods=['GET', 'POST'])
@login_required
def coaster_details(coaster_id):
    coaster = Coaster.query.get_or_404(coaster_id)
    review_form = ReviewForm()

    if review_form.validate_on_submit():
        new_review = Review(
            user_id=current_user.id,
            coaster_id=coaster_id,
            rating=review_form.rating.data,
            content=review_form.content.data
        )
        db.session.add(new_review)
        db.session.commit()
        flash('Review added successfully!')
        return redirect(url_for('coaster_details', coaster_id=coaster_id))

    reviews = (db.session.query(Review, User.username)
                .join(User, User.id == Review.user_id)
                .filter(Review.coaster_id == coaster_id)
                .all())

    return render_template('coaster_details.html', coaster=coaster, reviews=reviews, review_form=review_form)

@app.route('/add_to_top_ten', methods=['POST'])
@login_required
def add_to_top_ten():
    coaster_id = request.form.get('coaster_id')
    rank = request.form.get('rank')
    existing_entry = TopTenFavorite.query.filter_by(user_id=current_user.id, rank=rank).first()
    if existing_entry:
        flash('Rank already filled, please remove the existing coaster first.', 'error')
        return redirect(url_for('dashboard'))
    
    new_favorite = TopTenFavorite(user_id=current_user.id, coaster_id=coaster_id, rank=rank)
    db.session.add(new_favorite)
    db.session.commit()
    flash('Coaster added successfully!', 'success')
    return redirect(url_for('dashboard'))


def insert_coasters_from_csv(csv_file):
    with open(csv_file, 'r', newline='', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)
        id=0
        for row in csv_reader:
            name = row['Name'].strip()
            park = row.get('Park', '').strip()
            location = row.get('Location', '').strip()

            if Coaster.query.filter_by(name=name, park=park, location=location).first():
                continue 

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
            try:
                db.session.add(coaster)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
            except Exception as e:
                print(f"Failed to insert {name} at {park} in {location}: {e}")
                db.session.rollback()


if __name__ == "__main__": 
    with app.app_context(): 
        db.create_all() 
        insert_coasters_from_csv('every_operating_coaster.csv')
    app.run(debug=True)