import csv, os
from io import StringIO
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response, abort
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from email_validator import validate_email
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from functools import wraps
from dotenv import load_dotenv

# Erstelle die Flask App-Instanz
app = Flask(__name__)

# Mail-Konfiguration
app.config['MAIL_SERVER'] = 'mail.gmx.net'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
# aus .env datei, die nicht auf Git hochgeladen wird

load_dotenv()
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)

# Für die FLASK SQL Datenbank
app.secret_key = 'supersecretkey'  # Für Flash-Nachrichten erforderlich
# Datenbank-Konfiguration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///entries.db'  # SQLite-Datenbank
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Deaktiviert die Änderungsverfolgung (empfohlen)
# Datenbank initialisieren
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Benutzer-Modell für die Anmeldung
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='User')  # Rolle hinzufügen
    last_login = db.Column(db.DateTime, nullable=True)  # Neues Feld für den letzten Login
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Datenbankmodell für Einträge erstellen. Diese werden dann später aufgerufen.
class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    Platz10 = db.Column(db.String(100), nullable=True)
    Platz9 = db.Column(db.String(100), nullable=True)
    Platz8 = db.Column(db.String(100), nullable=True)
    Platz7 = db.Column(db.String(100), nullable=True)
    Platz6 = db.Column(db.String(100), nullable=True)
    Platz5 = db.Column(db.String(100), nullable=True)
    Platz4 = db.Column(db.String(100), nullable=True)
    Platz3 = db.Column(db.String(100), nullable=True)
    Platz2 = db.Column(db.String(100), nullable=True)
    Platz1 = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Route zum Anzeigen des Formulars
@app.route('/')
def index():
    return redirect(url_for('login'))  # Leitet zum Login weiter

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Registrierungs-Formular
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)

        if form.email.data == 'l.henkes@gmx.de':
            role = 'Admin'
        else:
            role = 'User'

        new_user = User(email=form.email.data, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash("Registrierung erfolgreich! Bitte melde dich an.")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Login-Formular
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Route für Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            user.last_login = datetime.utcnow()  # Letzter Login wird gesetzt
            db.session.commit()  # Speichert den neuen Wert
            return redirect(url_for('form'))
        else:
            flash("Login fehlgeschlagen. Bitte überprüfe deine Email und dein Passwort.")
    return render_template('login.html', form=form)

# Dekorator für Admin-Berechtigungen. Sonst kennt er unten nicht @admin_required
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'Admin':  # Überprüfen, ob der Benutzer Admin ist
            abort(403)  # Zugriff verweigert
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/manage_users')
@login_required
@admin_required  # Nur Admins haben Zugriff
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/update_role/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def update_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')

    if new_role in ['User', 'Admin'] and new_role != user.role:
        user.role = new_role
        db.session.commit()
        flash(f'Rolle von {user.email} erfolgreich auf {new_role} geändert!', 'success')

    return redirect(url_for('manage_users'))

# Route zum Abmelden
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Fehlerbehandlung für 403 - Zugriff verweigert
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

# Route für das Eintragsformular, nur für angemeldete Benutzer
@app.route('/form', methods=['GET', 'POST'])
@login_required
def form():
    existing_entry = Entry.query.filter_by(user_id=current_user.id).first()
    if request.method == 'POST':
        # Daten aus dem Formular abfragen und speichern
        email = request.form.get('email')
        Platz10 = request.form.get('Platz10')
        Platz9 = request.form.get('Platz9')
        Platz8 = request.form.get('Platz8')
        Platz7 = request.form.get('Platz7')
        Platz6 = request.form.get('Platz6')
        Platz5 = request.form.get('Platz5')
        Platz4 = request.form.get('Platz4')
        Platz3 = request.form.get('Platz3')
        Platz2 = request.form.get('Platz2')
        Platz1 = request.form.get('Platz1')



        # Validierung: Überprüfe, ob alle Felder ausgefüllt sind
        if not Platz10 or not Platz9 or not Platz8 or not Platz7 or not Platz6 or not Platz5 or not Platz4 or not Platz3 or not Platz2 or not Platz1:
            flash("Alle Felder müssen ausgefüllt sein!", "error")
            return redirect(url_for('form'))

        # Wenn der Benutzer bereits einen Eintrag hat, diesen aktualisieren
        if existing_entry:
            existing_entry.email = email
            existing_entry.Platz10 = Platz10
            existing_entry.Platz9 = Platz9
            existing_entry.Platz8 = Platz8
            existing_entry.Platz7 = Platz7
            existing_entry.Platz6 = Platz6
            existing_entry.Platz5 = Platz5
            existing_entry.Platz4 = Platz4
            existing_entry.Platz3 = Platz3
            existing_entry.Platz2 = Platz2
            existing_entry.Platz1 = Platz1

        else:
            # Neuer Eintrag, falls noch keiner existiert
            new_entry = Entry(
                user_id=current_user.id, email=email,
                Platz10=Platz10, Platz9=Platz9, Platz8=Platz8,
                Platz7=Platz7, Platz6=Platz6, Platz5=Platz5,
                Platz4=Platz4, Platz3=Platz3, Platz2=Platz2,
                Platz1=Platz1
            )
            db.session.add(new_entry)
        db.session.commit()

        #Überprüfen, ob die Checkbox aktiviert ist
        send_email = request.form.get('sendEmail')  # Gibt 'on' zurück, wenn die Checkbox ausgewählt wurde

        #MAIL formatierung
        if send_email:
            subject = "Bestätigung: Teilnahme am Goldenen Berti 2024"
            body = f"""
            Hallo Freund,

            Vielen Dank für deine Teilnahme am Goldenen Berti 2024!

            Hier sind deine Platzierungen der Brettspiele:

            Platz 10: {Platz10}
            Platz 9: {Platz9}
            Platz 8: {Platz8}
            Platz 7: {Platz7}
            Platz 6: {Platz6}
            Platz 5: {Platz5}
            Platz 4: {Platz4}
            Platz 3: {Platz3}
            Platz 2: {Platz2}
            Platz 1: {Platz1}

            Du kannst deine Eingaben jederzeit ändern, indem du dich wieder anmeldest: http://localhost:5000/login

            Mit freundlichen Grüßen,
            Das Team vom Goldenen Berti
            """

            msg = Message(subject, recipients=[email], sender=app.config['MAIL_USERNAME'])
            msg.body = body
            mail.send(msg)

        flash("Eintrag gespeichert.")
        return redirect(url_for('thankyou'))
        #return redirect(url_for('form'))


    # Wenn der Benutzer bereits einen Eintrag hat, wird dieser angezeigt
    return render_template('form.html', entry=existing_entry)

# Route zum Anzeigen aller Einträge (optional, nur für Admins)
@app.route('/entries')
@login_required
def entries():
    all_entries = Entry.query.all()
    return render_template('entry.html', entries=all_entries)

@app.route('/autocomplete')
def autocomplete():
    query = request.args.get('query')
    if not query:
        return jsonify([])

    try:
        with open('static/brettspiele.txt', 'r', encoding='utf-8') as f:
            brettspiele = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        return jsonify([])

    matches = [spiel for spiel in brettspiele if query.lower() in spiel.lower()]

    return jsonify(matches[:10])

# Route zur Bestätigungsseite
@app.route('/thankyou')
@login_required
def thankyou():
    return render_template('thankyou.html')

@app.route('/export')
@login_required
@admin_required
def export_csv():
    all_entries = Entry.query.all()

    si = StringIO()
    cw = csv.writer(si)

    cw.writerow(['ID', 'Email', 'date', 'Brettspiel Platz 10','Brettspiel Platz 9','Brettspiel Platz 8','Brettspiel Platz 7','Brettspiel Platz 6','Brettspiel Platz 5','Brettspiel Platz 4','Brettspiel Platz 3','Brettspiel Platz 2','Brettspiel Platz 1'])

    for entry in all_entries:
        cw.writerow([entry.id,  entry.email, entry.created_at, entry.Platz10,entry.Platz9,entry.Platz8,entry.Platz7,entry.Platz6,entry.Platz5,entry.Platz4,entry.Platz3,entry.Platz2,entry.Platz1])

    output = si.getvalue()
    si.close()

    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=entries.csv"})

# Datenbank erstellen und die Anwendung starten
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
