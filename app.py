from flask import Flask, render_template, request, redirect, url_for, flash
# from errors import page_not_found, internal_server_error  # Import des erreurs

from flask_wtf import FlaskForm # Formulaire

# Login
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Clé secrète pour les sessions


###################################### Configuration de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Définition de la classe utilisateur
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

# Simuler une base de données d'utilisateurs
users = {
    "admin": User(id="1", username="admin", password="password123")
}

@login_manager.user_loader
def load_user(user_id):
    #return users.get("admin") if users["admin"].id == user_id else None
    for user in users.values():
        if user.id == user_id:
            return user
    return None


###################################### Route

########### Session de connexion
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
        if user and user.password == form.password.data:
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