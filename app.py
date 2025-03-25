from flask import Flask, render_template, request, redirect, url_for, flash, session
# from errors import page_not_found, internal_server_error  # Import des erreurs

from flask_wtf import FlaskForm # Formulaire

# Login
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from flask_sqlalchemy import SQLAlchemy # Base de données

# Sécurité
from werkzeug.security import generate_password_hash, check_password_hash

import os
import time

app = Flask(__name__)
app.secret_key = os.urandom(24) # Clé secrète aléatoire pour les sessions
#app.secret_key = 'supersecretkey'  # Clé secrète pour les sessions
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tickets.db'
db = SQLAlchemy(app)

###################################### Configuration
########### Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

########### Cookie
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Mettre sur False en local si pas en HTTPS
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

###################################### Base de données
########### Utilisateur
class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

########### Ticketing
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(50), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

########### Initialisation de la base de données
with app.app_context():
    db.create_all()

    # Ajouter un utilisateur admin
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', is_admin=True)
        admin_user.set_password('admin')
        db.session.add(admin_user)

    # Ajouter un utilisateur non admin
    if not User.query.filter_by(username='user').first():
        regular_user = User(username='user', is_admin=False)
        regular_user.set_password('user')
        db.session.add(regular_user)

    db.session.commit()


###################################### Formulaire
# Formulaire de connexion sécurisé
class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')

# Formulaire de ticket
class TicketForm(FlaskForm):
    title = StringField('Titre', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    #priority = SelectField('Priorité', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')])
    submit = SubmitField('Soumettre')
class UpdateTicketForm(FlaskForm):
    title = StringField('Titre', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    priority = SelectField('Priorité', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')])
    submit = SubmitField('Mettre à jour')

###################################### Route
########### page d'accueil
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            if user.is_admin:
                flash("Connexion réussie !", "success")
                return redirect(url_for('admin'))
            else:
                flash("Connexion réussie !", "success")
                return redirect(url_for('home'))
        else:
            flash("Nom d'utilisateur ou mot de passe incorrect", "danger")
    return render_template('index.html', form=form, message="Bienvenue sur Flask")

########### Utilisateur
# Page après connexion utilisateur
@app.route('/home')
@login_required
def home():
    return render_template('home.html')

# Soumettre un ticket
@app.route('/submit_ticket', methods=['GET', 'POST'])
@login_required
def submit_ticket():
    form = TicketForm()
    if form.validate_on_submit():
        new_ticket = Ticket(
            title=form.title.data,
            description=form.description.data,
            #priority=form.priority.data,
            user_id=current_user.id
        )
        db.session.add(new_ticket)
        db.session.commit()
        flash("Ticket soumis avec succès !", "success")
        return redirect(url_for('home'))
    return render_template('submit_ticket.html', form=form)

########### Admin
# Page après connexion admin
@app.route('/admin')
@login_required
def admin():
    tickets = Ticket.query.all()
    return render_template('admin.html', tickets=tickets)

@app.route('/update/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def update_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    form = UpdateTicketForm(obj=ticket)

    if form.validate_on_submit():
        ticket.title = form.title.data
        ticket.description = form.description.data
        ticket.priority = form.priority.data
        db.session.commit()
        flash("Ticket mis à jour avec succès !", "success")
        return redirect(url_for('admin'))
    return render_template('update_ticket.html', form=form)

########### Déconnexion
# Route de déconnexion
@app.route('/logout')
@login_required
def logout():
    logout_user()
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
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

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
@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template("500.html"), 500

###################################### Main
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)