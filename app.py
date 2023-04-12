from flask_bcrypt import Bcrypt
from flask import Flask, render_template, redirect, url_for, flash
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, SubmitField, BooleanField, StringField
from wtforms.validators import DataRequired, EqualTo, Length, ValidationError
from flask_login import login_user, LoginManager, logout_user, UserMixin, login_required, current_user
from utils import get_time_now
import os
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY')
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)


class UserModel(db.Model, UserMixin):
    __tablename__ = "auth_user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    notes = db.relationship("NoteModel", backref="user", lazy=True)

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password, password)

    @staticmethod
    def generate_hashed_password(raw_password: str) -> str:
        return bcrypt.generate_password_hash(raw_password)


class NoteModel(db.Model, UserMixin):
    __tablename__ = "note"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    content = db.Column(db.String(2048), nullable=False)
    time_create = db.Column(db.String(128), default=get_time_now)
    user_id = db.Column(db.Integer, db.ForeignKey(UserModel.id), nullable=False)


class SignUpForm(FlaskForm):
    email = EmailField("Email", [DataRequired(), Length(max=128)])
    password = PasswordField("Password", [DataRequired(), Length(max=128)])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Sign Up")

    def validate_email(self, email: EmailField) -> None:
        user = UserModel.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError("This email is already registered.")


class SignInForm(FlaskForm):
    email = EmailField("Email", [DataRequired(), Length(max=128)])
    password = PasswordField("Password", [DataRequired(), Length(max=128)])
    remember = BooleanField("Remember Me", default=True)

    submit = SubmitField("Sign In")


class CreateNoteForm(FlaskForm):
    title = StringField("Title", [DataRequired(), Length(max=128)])
    content = StringField("Content", [DataRequired(), Length(max=2048)])

    submit = SubmitField("Create")


@login_manager.user_loader
def load_user(user_id):
    return UserModel.query.get(int(user_id))


@app.route('/')
def note_list():
    notes = NoteModel.query.all()
    return render_template("note_list.html", object_list=notes)


@app.route('/create/', methods=["GET", "POST"])
@login_required
def note_create():
    form = CreateNoteForm()

    if form.validate_on_submit():
        db.session.add(
            NoteModel(
                title=form.title.data,
                content=form.content.data,
                user_id=current_user.id,
            )
        )
        db.session.commit()

        flash("You create note", "success")

        return redirect(url_for("note_list"))

    return render_template("note_create.html", form=form)


@app.route('/delete/<int:pk>', methods=["GET", "POST"])
@login_required
def note_delete(pk: int):
    note: NoteModel = NoteModel.query.get_or_404(pk)

    if note.user_id != current_user.id:
        return redirect(url_for("note_list"))

    if note is not None:
        db.session.delete(note)
        db.session.commit()

        flash("You deleted a note", "danger")

    return redirect(url_for("note_list"))


@app.route('/update/<int:pk>', methods=["GET", "POST"])
@login_required
def note_update(pk: int):
    note: NoteModel = NoteModel.query.get_or_404(pk)
    form = CreateNoteForm()

    if note.user_id != current_user.id:
        return redirect(url_for("note_list"))

    if form.validate_on_submit():
        note.title = form.title.data
        note.content = form.content.data

        db.session.add(note)
        db.session.commit()

        flash("Time report has been updated", "success")

        return redirect(url_for("note_list"))

    return render_template("note_update.html", form=form, note=note)


@app.route('/signup/', methods=["POST", "GET"])
def signup():
    form = SignUpForm()

    if form.validate_on_submit():
        db.session.add(
            UserModel(
                email=form.email.data,
                password=UserModel.generate_hashed_password(form.password.data)
            )
        )
        db.session.commit()

        flash("Account created. You can login now.", "success")

        return redirect(url_for("signin"))

    return render_template("signup.html", form=form)


@app.route('/signin/', methods=["POST", "GET"])
def signin():
    form = SignInForm()

    if form.validate_on_submit():
        user = UserModel.query.filter_by(email=form.email.data).first()

        if user is not None and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for("note_list"))

        else:
            flash("Incorrect username or password. Please check.", "danger")

    return render_template("signin.html", form=form)


@app.route('/logout/')
def logout():
    logout_user()

    flash("You are logged out", "success")

    return redirect(url_for("note_list"))


@app.route('/user/')
@login_required
def user():
    notes_user: NoteModel = NoteModel.query.filter_by(user_id=current_user.id)

    return render_template("user.html", object_list=notes_user)


if __name__ == '__main__':
    app.run(debug=True)
