import re

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
# from errors import page_not_found, internal_server_error  # Import des erreurs

from flask_wtf import FlaskForm # Formulaire
import subprocess

from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename
# Login
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from flask_sqlalchemy import SQLAlchemy # Base de données

# Sécurité
from werkzeug.security import generate_password_hash, check_password_hash

import os
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv
import pymysql

email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

app = Flask(__name__)
load_dotenv()

###################################### Configuration
########### Configuration de la clé secrète
#app.secret_key = os.urandom(24) # Clé secrète aléatoire pour les sessions
app.secret_key = os.getenv('SECRET_KEY')  # Clé secrète pour les sessions

########### Configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Mettre sur False en local si pas en HTTPS
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
# app.config['UPLOAD_FOLDER'] = 'attachments'
UPLOAD_ROOT = "attachments"

########### Base de données
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tickets.db'
#print(f"DB_HOST: {os.getenv('DB_HOST')}")
#print(f"DB_USER: {os.getenv('DB_USER')}")
#print(f"DB_PASSWORD: {os.getenv('DB_PASSWORD')}")
#print(f"DB_NAME: {os.getenv('DB_NAME')}")
#print(f"DB_PORT: {os.getenv('DB_PORT')}")
#app.config['SQLALCHEMY_DATABASE_URI'] = (
#    f"mysql+mysqlconnector://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}"
#    f"@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
#)
#app.config['SQLALCHEMY_DATABASE_URI'] = (
#    f"mysql+mysqlconnector://{os.getenv('DB_USER')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
#)

#pymysql.install_as_MySQLdb()
db = SQLAlchemy(app)

########### Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

###################################### Base de données
########### Utilisateur
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    #username = db.Column(db.String(80), unique=True, nullable=False)
    mail = db.Column(db.String(80), unique=True, nullable=False)
    nom = db.Column(db.String(80), unique=False, nullable=False)
    prenom = db.Column(db.String(80), unique=False, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.id}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def add_user(mail, nom, prenom, password):
    #new_user = User(mail=mail, username=username, nom=nom, prenom=prenom)
    new_user = User(mail=mail, nom=nom, prenom=prenom)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    # flash("Utilisateur ajouté avec succès.", category="success")
    return new_user


########### Tickets
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(50), nullable=False, default='Ouvert')
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('tickets', lazy=True))
    attachment_path = db.Column(db.String(255), nullable=True)

########### Messages
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow())
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Si l'admin a écrit le message

    ticket = db.relationship('Ticket', backref=db.backref('messages', lazy=True))
    user = db.relationship('User', backref=db.backref('messages', lazy=True))



###################################### Formulaire
# Formulaire de connexion sécurisé
class LoginForm(FlaskForm):
    #username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    mail = StringField('Mail', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')


# Formulaire d'inscription
class SignInForm(FlaskForm):
    mail = StringField('Mail', validators=[DataRequired()])
    #username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    nom = StringField('Nom', validators=[DataRequired()])
    prenom = StringField('Prenom', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    password_confirm = PasswordField('Confirmation de mot de passeBLBLALALBALBA', validators=[DataRequired()])
    submit = SubmitField("S'inscrire")

# Formulaire de ticket
class TicketForm(FlaskForm):
    title = StringField('Titre', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    # Champ de fichier
    attachment = FileField('Fichier', validators=[])
    #priority = SelectField('Priorité', choices=[('Basse', 'Basse'), ('Moyen', 'Moyen'), ('Haute', 'Haute')])
    submit = SubmitField('Soumettre')

class UpdateTicketForm(FlaskForm):
    title = StringField('Titre', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    priority = SelectField('Priorité', choices=[('Basse', 'Basse'), ('Moyen', 'Moyen'), ('Haute', 'Haute')])
    status = SelectField('Status', choices=[('Ouvert', 'Ouvert'), ('Fermé', 'Fermé')], validators=[DataRequired()])
    submit = SubmitField('Mettre à jour')

# Formulaire de message
class ChatForm(FlaskForm):
    content = StringField('Titre', validators=[DataRequired()])
    submit = SubmitField('Envoyer')



###################################### Route
###########Connexion

@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # user = User.query.filter_by(username=form.username.data).first()
        user = User.query.filter_by(mail=form.mail.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            session.permanent = True
            # session["username"] = user.username
            session["mail"] = user.mail
            session["user_id"] = user.id  # Stocke aussi l'ID utilisateur
            session["is_admin"] = user.is_admin  # Stocke le statut admin
            if user.is_admin:
                flash("Connexion réussie !", "success")
                return redirect(url_for('admin'))
            else:
                flash("Connexion réussie !", "success")
                return redirect(url_for('home'))
        else:
            flash("Nom d'utilisateur ou mot de passe incorrect", "danger")
    return render_template('login.html', form=form, message="Bienvenue sur Flask")

###########Inscription
@app.route('/sign_in', methods=['GET', 'POST'])
def sign_in():
    form = SignInForm()
    if form.validate_on_submit():
        if not re.match(email_regex, form.mail.data)  :
            flash("L\'adresse email n\'est pas valide.", "danger")
        if form.password.data != form.password_confirm.data:
            flash("Les mots de passe ne correspondent pas", "danger")
        # elif User.query.filter_by(username=form.username.data).first():
        elif User.query.filter_by(mail=form.mail.data).first():
            flash("Cet email est deja utilisé", "danger")
        else:
            # add_user(form.mail.data, form.username.data, form.nom.data, form.prenom.data, form.password.data)
            add_user(form.mail.data, form.nom.data, form.prenom.data, form.password.data)

            return redirect(url_for('login'))
    return render_template('sign_in.html', message="Bienvenue sur Flask", form=form)

########### Utilisateur
# Page après connexion utilisateur
@app.route('/home')
@login_required
def home():
    if current_user.is_admin: # Vérifie si l'utilisateur est un administrateur
        flash("Vous n'avez pas les droits nécessaires pour accéder à cette page.", "danger")
        return redirect(url_for('admin'))

    #username = session.get("username")
    mail = session.get("mail")
    tickets = Ticket.query.filter_by(user_id=current_user.id).all()
    # return render_template('home.html', tickets=tickets, username=username)
    return render_template('home.html', tickets=tickets, mail=mail)



# Soumettre un ticket
def save_file(file, user_id, ticket_id):
    # Cree le chemin : attachments/user_3/ticket_12/
    folder_path = os.path.join(UPLOAD_ROOT, f"user_{user_id}", f"ticket_{ticket_id}")
    os.makedirs(folder_path, exist_ok=True)

    # Nettoie le nom du fichier et sauvegarde
    filename = secure_filename(file.filename)
    filepath = os.path.join(folder_path, filename)
    file.save(filepath)

    return filepath

@app.route('/submit_ticket', methods=['GET', 'POST'])
@login_required
def submit_ticket():
    if current_user.is_admin: # Vérifie si l'utilisateur est un administrateur
        flash("Vous n'avez pas les droits nécessaires pour accéder à cette page.", "danger")
        return redirect(url_for('admin'))

    form = TicketForm()
    if form.validate_on_submit():
        new_ticket = Ticket(
            title=form.title.data,
            description=form.description.data,
            #priority=form.priority.data,
            user_id=current_user.id
        )
        db.session.add(new_ticket) #pour que le ticket aie un id
        db.session.commit()

        attachment = form.attachment.data
        if attachment:
            filepath = save_file(attachment, current_user.id, new_ticket.id)
            new_ticket.attachment_path = filepath
            db.session.commit()

        flash("Ticket soumis avec succès !", "success")
        return redirect(url_for('home'))
    return render_template('submit_ticket.html', form=form)

########### Admin
# Page après connexion admin
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin: # Vérifie si l'utilisateur est un administrateur
        flash("Vous n'avez pas les droits nécessaires pour accéder à cette page.", "danger")
        return redirect(url_for('home'))

    #username = session.get("username")
    mail = session.get("mail")
    tickets = Ticket.query.join(User, Ticket.user_id == User.id).all()
    #return render_template('admin.html', tickets=tickets, username=username)
    return render_template('admin.html', tickets=tickets, mail=mail)


@app.route('/update/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def update_ticket(ticket_id):
    if not current_user.is_admin: # Vérifie si l'utilisateur est un administrateur
        flash("Vous n'avez pas les droits nécessaires pour accéder à cette page.", "danger")
        return redirect(url_for('home'))

    ticket = Ticket.query.get_or_404(ticket_id)
    form = UpdateTicketForm(obj=ticket)

    if form.validate_on_submit():
        ticket.title = form.title.data
        ticket.description = form.description.data
        ticket.priority = form.priority.data
        ticket.status = form.status.data
        db.session.commit()
        flash("Ticket mis à jour avec succès !", "success")
        return redirect(url_for('admin'))
    return render_template('update_ticket.html', form=form)

########### Chat
@app.route('/ticket/<int:ticket_id>/chat', methods=['GET', 'POST'])
@login_required
def chat(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    if( current_user.id != ticket.user_id and not current_user.is_admin ):
        return page_forbidden("test")
    else:

        messages = Message.query.filter_by(ticket_id=ticket_id).all()

        form = ChatForm()
        if form.validate_on_submit():
            new_message = Message(
                content=form.content.data,
                ticket_id=ticket_id,
                user_id=current_user.id,
                is_admin = current_user.is_admin,
            )
            db.session.add(new_message)
            db.session.commit()

            return redirect(url_for('chat', ticket_id=ticket_id))


        return render_template('chat.html', ticket=ticket, form=form, messages=messages)


@app.route('/download/<int:ticket_id>')
@login_required
def download_attachment(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    # Vérifier si l'utilisateur a le droit d'accéder à cette pièce jointe
    if current_user.id != ticket.user_id and not current_user.is_admin:
        return page_forbidden("Non autorisé à accéder à cette pièce jointe")

    # Vérifier si la pièce jointe existe
    if not ticket.attachment_path or not os.path.exists(ticket.attachment_path):
        flash("Pièce jointe non trouvée", "danger")
        return redirect(url_for('home'))

    # Extraire le nom de fichier original à partir du chemin
    filename = os.path.basename(ticket.attachment_path)

    # Envoyer le fichier
    return send_file(ticket.attachment_path, download_name=filename, as_attachment=True)

########### Déconnexion
@app.route('/logout')
@login_required
def logout():
    logout_user()
    # session.pop("username", None)  # Supprime le nom d'utilisateur
    session.pop("mail", None)  # Supprime l'email'
    session.pop("user_id", None)  # Supprime l'ID utilisateur
    session.pop("is_admin", None)  # Supprime le statut admin
    session.clear()
    flash("Déconnexion réussie !", "success")
    return redirect(url_for('login'))


###################################### Sécurité
########### Protection contre le brute-force
failed_attempts = {}  # Stocke le nombre de tentatives échouées
blocked_ips = {}  # Stocke les IP temporairement bloquées

@app.before_request
def block_brute_force():
    ip = request.remote_addr

    # Vérifie si l'IP est temporairement bloquée
    if ip in blocked_ips:
        time_since_block = time.time() - blocked_ips[ip]
        if time_since_block < 10:  # 300 secondes = 5 minutes
            session['blocked'] = True  # Stocke l'info dans la session
            return redirect(url_for('login')) # Redirige l'utilisateur vers la page de connexion
        else:
            del blocked_ips[ip]  # Supprime l'IP après 5 minutes de blocage
            session.pop('blocked', None)  # Nettoie la session

@app.after_request
def track_failed_attempts(response):
    if request.endpoint == 'login' and request.method == 'POST':  # Si tentative de connexion
        ip = request.remote_addr # Récupère l'adresse IP du client
        # username = request.form.get('username')
        mail = request.form.get('mail')
        password = request.form.get('password')

        # user = User.query.filter_by(username=username).first()
        user = User.query.filter_by(mail=mail).first()

        if not user or not user.check_password(password):  # Si échec
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1  # Augmente le compteur

            if failed_attempts[ip] >= 5:  # Après 5 échecs
                blocked_ips[ip] = time.time()  # Bloque l'IP pendant 5 minutes
                session['blocked'] = True  # Stocke dans la session
                return redirect(url_for('login'))  # Redirige immédiatement
        else:
            failed_attempts[ip] = 0  # Réinitialise le compteur après un succès
            session.pop('blocked', None)  # Supprime l'état de blocage
    return response

###################################### Gestion des erreurs
@app.errorhandler(403)
def page_forbidden(error):
    return render_template("403.html"), 403

@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template("500.html"), 500

###################################### Main
if __name__ == '__main__':
    # subprocess.run(['python', 'build_db.py'], check=True)
    app.run(host='127.0.0.1', port=5000, debug=True, threaded=True)
    #app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)