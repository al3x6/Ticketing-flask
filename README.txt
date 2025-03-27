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