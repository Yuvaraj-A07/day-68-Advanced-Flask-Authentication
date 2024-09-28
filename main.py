from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# WE NEED TO CONFIGURE OUR FLASK'S LOGIN PAGE
login_manager = LoginManager()
login_manager.init_app(app)


# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE TABLE IN DB using UserMixin
class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    # this is for the user who are created their account for first time
    if request.method == "POST":
        data = request.form
        name = data["name"]
        email = data["email"]
        password = data['password']

        # Find user by email entered.
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if not user:
            hs_password = generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=8)

            new_user = User(name=name, email=email, password=hs_password)
            db.session.add(new_user)
            db.session.commit()
            # Log in and authenticate user after adding details to database.
            login_user(new_user)

            # Can redirect() and get name from the current_user
            return redirect(url_for("secrets"))
            # return render_template("secrets.html", name=request.form.get('name'))
        else:
            flash("You have already signed up with this email, please login instead")
            return redirect(url_for('login'))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        # Find user by email entered.
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        if user:
            # Check stored password hash against entered password hashed.
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('secrets'))
            else:
                flash("Password incorrect, please try again.")
                return redirect(url_for('login'))
        else:
            flash("The email does not exits, please try again.")
            return redirect(url_for('login'))

    return render_template("login.html", logged_in=current_user.is_authenticated)

    # return render_template("login.html")

# Only logged-in users can access the route
@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    # Passing the name from the current_user
    return render_template("secrets.html", name=current_user.name, logged_in=True)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

# only authenticated user can download the file

@app.route('/download', methods=["GET", "POST"])
@login_required
def download():
    return send_from_directory(directory="./static/files", path="cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
