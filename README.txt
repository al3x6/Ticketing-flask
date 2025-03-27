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
