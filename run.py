from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
import os
import hashlib
import random
import string
from sqlalchemy.exc import IntegrityError  # Import IntegrityError
import requests

app = Flask(__name__)
app.secret_key = 'd62b3f60a87e52ef5bb71afcaf2618f1'  # Change this to a secure secret key
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}

# Configure SQLAlchemy to use SQLite and create the users table
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Create a LoginManager instance for handling user sessions
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    number = db.Column(db.String)
    identification_number = db.Column(db.String, unique=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String)

   # Relationships with art, owned_art, and cart_items
    art = db.relationship("Art", back_populates="user", foreign_keys='Art.user_id')
    owned_art = db.relationship("Art", back_populates="owner", foreign_keys='Art.owner_id')
    cart_items = db.relationship("CartItem", back_populates="user", cascade="all, delete-orphan")


class CartItem(db.Model):
    __tablename__ = 'cart_items'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    art_id = db.Column(db.Integer, db.ForeignKey('arts.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    art = db.relationship("Art", back_populates="cart_items")
    user = db.relationship("User", back_populates="cart_items")


class Art(db.Model):
    __tablename__ = 'arts'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String)
    description = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id')) 
    price = db.Column(db.Float, nullable=False)
    image_filename = db.Column(db.String)  # New column to store the filename
    
    user = db.relationship("User", back_populates="art", foreign_keys=[user_id])
    owner = db.relationship("User", back_populates="owned_art", foreign_keys=[owner_id])
    
    cart_items = db.relationship("CartItem", back_populates="art", cascade="all, delete-orphan")



# Function to generate a unique identification number
def generate_unique_identification_number():
    while True:
        # Generate a random 6-character alphanumeric string
        identification_number = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

        # Check if the generated identification_number is already in use
        user = User.query.filter_by(identification_number=identification_number).first()

        # If no user with this identification_number exists, return it
        if user is None:
            return identification_number

# Function to check if a file has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        number = request.form['number']
        email = request.form['email']
        password = request.form['password']

        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Generate a unique identification number
        identification_number = generate_unique_identification_number()

        try:
            # Insert user data into the database
            new_user = User(name=name, number=number, identification_number=identification_number, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            flash(f'Registration successful! Welcome, {name}! Your Identification Number: {identification_number}', 'success')
            return redirect(url_for('login'))
        except IntegrityError as e:
            db.session.rollback()
            flash('Registration failed. This email or identification number is already in use.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. An error occurred.', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Hash the password for comparison
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Check if the user exists in the database using SQLAlchemy
        user = User.query.filter_by(email=email, password=hashed_password).first()

        if user is not None:
            login_user(user)
            flash(f'Login successful! Welcome, {user.name}!', 'success')
            return redirect(url_for('art'))
        else:
            flash('Login failed. Please check your email and password.', 'danger')

    return render_template('login.html')

    
@app.route('/art',methods=['GET','POST'])
@login_required
def art():
    art_items = db.session.query(Art).all()
    return render_template('art.html', art_items=art_items)

@app.route('/upload_art', methods=['POST'])
@login_required
def upload_art():
    art_name = request.form['art_name']
    price = float(request.form['price'])

    if 'art_image' in request.files:
        art_image = request.files['art_image']
        if allowed_file(art_image.filename):
            filename = secure_filename(art_image.filename)
            art_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            new_art = Art(title=art_name, description="", image_filename=filename, price=price, owner=current_user)
            db.session.add(new_art)
            db.session.commit()

            flash('Art uploaded successfully!', 'success')
        else:
            flash('Invalid file type. Allowed types are jpg, jpeg, png, gif.', 'danger')
    else:
        flash('No file uploaded.', 'danger')

    return redirect(url_for('profile'))

@app.route('/buy_art/<int:art_id>', methods=['GET'])
@login_required
def buy_art(art_id):
    art = db.session.query(Art).get(art_id)

    if art and art.owner != current_user and art.price > 0:
        cart_item = CartItem(art=art, user=current_user)
        db.session.add(cart_item)
        db.session.commit()
        flash('Art added to your cart!', 'success')
    else:
        flash('Unable to add this art to your cart.', 'danger')

    return redirect(url_for('art'))
    
@app.route('/cart')
@login_required
def view_cart():
    cart_items = current_user.cart_items
    total_cost = sum(cart_item.art.price for cart_item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total_cost=total_cost)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.name = request.form['name']
        current_user.number = request.form['number']
        db.session.commit()
        flash('Profile updated successfully!', 'success')

    user_art = db.session.query(Art).filter_by(owner=current_user).all()

    return render_template('profile.html', user=current_user, user_art=user_art)

@app.route('/cart/remove/<int:cart_item_id>', methods=['GET'])
@login_required
def remove_from_cart(cart_item_id):
    cart_item = db.session.query(CartItem).get(cart_item_id)

    if cart_item and cart_item.user == current_user:
        db.session.delete(cart_item)
        db.session.commit()
        flash('Art removed from your cart!', 'success')
    else:
        flash('Unable to remove this art from your cart.', 'danger')

    return redirect(url_for('view_cart'))    
    


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
