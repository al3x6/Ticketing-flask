from flask import Flask, render_template, request, redirect, url_for, flash, session
# from errors import page_not_found, internal_server_error  # Import des erreurs

from flask_wtf import FlaskForm # Formulaire

# Login
from wtforms import StringField, PasswordField, SubmitField
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


###################################### Configuration

########### Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

########### Cookie
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Mettre sur False en local si pas en HTTPS
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

########### Utilisateur
# Définition de la classe utilisateur
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

# Simuler une base de données d'utilisateurs
users = {
    "admin": User(id="1", username="admin", password_hash=generate_password_hash("password123"))
}

@login_manager.user_loader
def load_user(user_id):
    #return users.get("admin") if users["admin"].id == user_id else None
    #return next((user for user in users.values() if user.id == user_id), None)
    for user in users.values():
        if user.id == user_id:
            return user
    return None


###################################### Route

########### Session de connexion
# Formulaire de connexion sécurisé
class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')

# Route de connexion (page d'accueil)
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = users.get(form.username.data)
        if user and user.verify_password(form.password.data):
            login_user(user)
            flash("Connexion réussie !", "success")
            return redirect(url_for('home'))
        else:
            flash("Nom d'utilisateur ou mot de passe incorrect", "danger")
    return render_template('index.html', form=form, message="Bienvenue sur Flask")

# Page après connexion
@app.route('/home')
@login_required
def home():
    return render_template('home.html')

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
        form = LoginForm()
        user = users.get(form.username.data)

        if not user or not user.verify_password(form.password.data):  # Si échec
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
    app.run(host='0.0.0.0', port=80, debug=True, threaded=True)