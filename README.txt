# Lancer le projet
git clone https://github.com/al3x6/Ticketing-flask.git

cd Ticketing-flask
python3 -m venv .venv
source .venv/bin/activate

pip install poetry          # Installer Poetry, seulement la premiere fois
pip install gunicorn
poetry lock
poetry install              # installer les dépendances du projet

poetry run python app.py   # Lancer l'application
gunicorn -w 4 -b [ip machine local] app:app


# A ne pas faire
Création d'un dossier -> L'ouvrir

poetry init                 # Initialiser, seulement la premiere fois, pour créer le projet
