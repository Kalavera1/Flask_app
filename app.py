import csv
from io import StringIO
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from email_validator import validate_email
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Wichtige Datei Pfade und Namen als Variablen
form_file = 'form.html'

app = Flask(__name__)
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

# Route für Registrierung
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = User(email=form.email.data, password=hashed_password)
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
            #flash("Login erfolgreich!")
            return redirect(url_for('form'))
        else:
            flash("Login fehlgeschlagen. Bitte überprüfe deine Email und dein Passwort.")
    return render_template('login.html', form=form)

# Route zum Abmelden
@app.route('/logout')
@login_required
def logout():
    logout_user()
    #flash("Du wurdest abgemeldet.")
    return redirect(url_for('login'))

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
        flash("Eintrag gespeichert.")
        return redirect(url_for('form'))

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

    #Überprüfen, ob das Brettspiel dictionary vorhanden ist oder nicht.
    try:
        with open('static/brettspiele.txt', 'r', encoding='utf-8') as f:
            brettspiele = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        return jsonify([])  # Leere Liste zurückgeben, falls Datei nicht gefunden wird

    # Vorschläge filtern
    matches = [spiel for spiel in brettspiele if query.lower() in spiel.lower()]

    return jsonify(matches[:10])  # Nur die ersten 5 Vorschläge zurückgeben

@app.route('/export')
def export_csv():
    # Abfrage aller Einträge in der Datenbank
    all_entries = Entry.query.all()

    # StringIO-Objekt, um die CSV-Datei in den Speicher zu schreiben
    si = StringIO()
    cw = csv.writer(si)

    # CSV-Header
    cw.writerow(['ID', 'Email', 'Brettspiel Platz 10'])

    # CSV-Inhalt (Einträge)
    for entry in all_entries:
        cw.writerow([entry.id, entry.email, entry.Platz10])

    # Die CSV-Datei zum Download bereitstellen
    output = si.getvalue()
    si.close()

    # Flask Response zur Rückgabe der CSV-Datei
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=entries.csv"})

# Datenbank erstellen und die Anwendung starten
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Erstellt die Datenbank und Tabellen, falls sie nicht existieren
    app.run(debug=True)