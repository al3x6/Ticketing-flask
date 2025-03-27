Création d'un dossier -> L'ouvrir

pip install poetry          # Installer Poetry, seulement la premiere fois

poetry init                 # Initialiser, seulement la premiere fois

poetry install              # installer les dépendances du projet

# Librairie :
poetry add flask
poetry add flask_wtf
poetry add flask_login
poetry add flask_sqlalchemy

poetry run python app.py   # Lancer l'application

----------------------------------- Ticketing
Partie Globale
* création de compte (inscription)


Partie Support
* Filtre des tickets
* Bouton cloturer dans la page admin.html
    + Message de cloturation
    + Validation de cloturation


Partie Utilisateur
* Créé deux utilisateurs
* Suivi de ses propres tickets (home.html)
* Communication messagerie avec le support

Schéma :
* Infrastructure : Élaborer l'architecture de l'application, en détaillant les composants clés (serveur, base de données, client) et leur interaction.
* Expliquer le choix des technologies et l'organisation de l'infrastructure pour garantir la scalabilité et la performance.
* Conception Base de données

Infra :
* Serveur redondant
* Service Base de données redondant
* Un reverse Proxy (avec nginx) sera utilisé pour répartir la charge et sécuriser les communications via TLS.
* Un Web Application Firewall (WAF) pour protéger l'application contre les attaques courantes telles que XSS ou injections SQL.
