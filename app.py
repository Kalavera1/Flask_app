import csv
from io import StringIO
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime #für Datum und Zeit

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

# Datenbankmodell für Einträge erstellen. Diese werden dann später aufgerufen.
class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    Platz10 = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Feld für Datum und Zeit

# Route zum Anzeigen des Formulars
@app.route('/')
def form():
    return render_template(form_file)

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
    cw.writerow(['ID', 'Name', 'Alter', 'Email', 'Brettspiel Platz 10'])

    # CSV-Inhalt (Einträge)
    for entry in all_entries:
        cw.writerow([entry.id, entry.name, entry.age, entry.email, entry.Platz10])

    # Die CSV-Datei zum Download bereitstellen
    output = si.getvalue()
    si.close()

    # Flask Response zur Rückgabe der CSV-Datei
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=entries.csv"})


# Route zum Verarbeiten des Formulars, wenn es abgeschickt wird per POST
@app.route('/submit', methods=['POST'])
def submit():
    name = request.form.get('name')
    age = request.form.get('age')
    email = request.form.get('email')
    Platz10 = request.form.get('Platz10')

    # Validierung der Eingaben
    if not name:
        flash("Der Name darf nicht leer sein!", "error")
        return redirect(url_for('form'))

    if not age.isdigit() or int(age) <= 0:
        flash("Bitte gib ein gültiges Alter ein!", "error")
        return redirect(url_for('form'))

    if not email:
        flash("Bitte geben Sie eine gültige E-Mail ein!", "error")
        return redirect(url_for('form'))

    # Prüfen, ob das Brettspiel für Platz 10 in der Textdatei existiert
    try:
        with open('static/brettspiele.txt', 'r', encoding='utf-8') as f:
            brettspiele = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        flash("Die Liste der Brettspiele konnte nicht geladen werden.", "error")
        return redirect(url_for('form'))

    if Platz10 not in brettspiele:
        flash("Bitte wähle ein Brettspiel aus der Liste für Platz 10!", "error")
        return redirect(url_for('form'))

    # Neue Benutzerdaten speichern
    new_entry = Entry(name=name, age=int(age), email=email, Platz10=Platz10)
    db.session.add(new_entry)
    db.session.commit()

    # Erfolgsmeldung
    flash(f"Neuer Eintrag für {name} mit dem Brettspiel: {Platz10} wurde erfolgreich hinzugefügt!", "success")
    return redirect(url_for('form'))

# Route zum Anzeigen aller Einträge
@app.route('/entries')
def entries():
    all_entries = Entry.query.all()  # Alle Einträge aus der Datenbank abfragen
    return render_template('entry.html', entries=all_entries)

# Datenbank erstellen und die Anwendung starten
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Erstellt die Datenbank und Tabellen, falls sie nicht existieren
    app.run(debug=True)