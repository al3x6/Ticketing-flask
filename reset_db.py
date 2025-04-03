from app import app, db

# Crée un contexte d'application pour pouvoir utiliser db
with app.app_context():
    # Supprimer toutes les tables
    db.drop_all()

    # Recréer les tables
    db.create_all()

    print("Base de données réinitialisée et tables recréées avec succès.")
