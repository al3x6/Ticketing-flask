from app import app, User,Ticket,db

with app.app_context():
    # Créer toutes les tables
    db.create_all()

    # Ajouter 5 utilisateurs
    users = [
        {"username": "admin1", "nom": "phan", "prenom": "marc", "mail": "admin1@mail.com", "is_admin": True, "password": "admin1"},
        {"username": "admin2", "nom": "arj", "prenom": "alexis", "mail": "admin2@mail.com", "is_admin": True, "password": "admin2"},
        {"username": "user1", "nom": "ohb", "prenom": "amine", "mail": "user1@mail.com", "is_admin": False, "password": "user1"},
        {"username": "user2", "nom": "boeing", "prenom": "jaques", "mail": "user2@mail.com", "is_admin": False, "password": "user2"},
        {"username": "user3", "nom": "hello", "prenom": "thibaut", "mail": "user3@mail.com", "is_admin": False, "password": "user3"},
    ]

    for user_data in users:
        if not User.query.filter_by(username=user_data['username']).first():
            user = User(username=user_data['username'], nom=user_data['nom'], prenom=user_data['prenom'], mail=user_data['mail'], is_admin=user_data['is_admin'])
            user.set_password(user_data['password'])
            db.session.add(user)

    # Ajouter 5 tickets associés aux utilisateurs
    tickets = [
        {"title": "Problème de connexion", "description": "L'utilisateur ne peut pas se connecter.", "user_id": 3},
        {"title": "Erreur de paiement", "description": "Erreur lors de la validation de paiement.", "user_id": 4},
        {"title": "Demande de remboursement", "description": "L'utilisateur souhaite être remboursé pour un achat.", "user_id": 3},
        {"title": "Question sur le produit", "description": "Demande d'information sur un produit.", "user_id": 4},
        {"title": "Problème de performance", "description": "Le site met trop de temps à charger.", "user_id": 5},
    ]

    for ticket_data in tickets:
        ticket = Ticket(title=ticket_data['title'], description=ticket_data['description'], user_id=ticket_data['user_id'])
        db.session.add(ticket)

    # Commit les changements dans la base de données
    db.session.commit()
    print("Jeu d'essai créé avec succès !")
