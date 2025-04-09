from app import app, User,Ticket,db

with app.app_context():
    # Créer toutes les tables
    db.create_all()

    # users = [
    #     {"username": "admin1", "nom": "phan", "prenom": "marc", "mail": "admin1@mail.com", "is_admin": True, "password": "admin1"},
    #     {"username": "admin2", "nom": "arj", "prenom": "alexis", "mail": "admin2@mail.com", "is_admin": True, "password": "admin2"},
    #     {"username": "user1", "nom": "ohb", "prenom": "amine", "mail": "user1@mail.com", "is_admin": False, "password": "user1"},
    #     {"username": "user2", "nom": "boeing", "prenom": "jaques", "mail": "user2@mail.com", "is_admin": False, "password": "user2"},
    #     {"username": "user3", "nom": "hello", "prenom": "thibaut", "mail": "user3@mail.com", "is_admin": False, "password": "user3"},
    # ]

    # for user_data in users:
    #     if not User.query.filter_by(username=user_data['username']).first():
    #         user = User(username=user_data['username'], nom=user_data['nom'], prenom=user_data['prenom'], mail=user_data['mail'], is_admin=user_data['is_admin'])
    #         user.set_password(user_data['password'])
    #         db.session.add(user)


    # Ajouter 5 utilisateurs
    users = [
        { "mail": "admin1@mail.com", "nom": "Dupont", "prenom": "Alice",  "is_admin": True, "password": "admin1"},
        { "mail": "admin2@mail.com", "nom": "Leroux", "prenom": "Bruno",  "is_admin": True, "password": "admin2"},
        { "mail": "user1@mail.com", "nom": "Moreau", "prenom": "Carla",  "is_admin": False, "password": "user1"},
        { "mail": "user2@mail.com", "nom": "Martin", "prenom": "Dylan",  "is_admin": False, "password": "user2"},
        { "mail": "user3@mail.com", "nom": "Fabre", "prenom": "Emma",  "is_admin": False, "password": "user3"},
    ]

    for user_data in users:
        if not User.query.filter_by(mail=user_data['mail']).first():
            user = User(mail=user_data['mail'], nom=user_data['nom'], prenom=user_data['prenom'], is_admin=user_data['is_admin'])
            user.set_password(user_data['password'])
            db.session.add(user)

    # Ajouter 5 tickets associés aux utilisateurs
    tickets = [
        {"title": "Tentative de phishing détectée", "description": "Un email suspect a été signalé par un employé. Analyse en cours.", "user_id": 3},
        {"title": "Infection par ransomware", "description": "Un poste utilisateur affiche une note de rançon. Isolation et triage en cours.", "user_id": 4},
        {"title": "Fuite de données sensibles", "description": "Des fichiers internes ont été retrouvés sur un forum public.", "user_id": 3},
        {"title": "Connexion suspecte à distance", "description": "Connexion RDP non autorisée détectée depuis une IP étrangère.", "user_id": 4},
        {"title": "Logiciel malveillant détecté sur serveur", "description": "Un exécutable inconnu s'exécute sur un serveur de production.", "user_id": 5},
    ]

    for ticket_data in tickets:
        ticket = Ticket(title=ticket_data['title'], description=ticket_data['description'], user_id=ticket_data['user_id'])
        db.session.add(ticket)

    # Commit les changements dans la base de données
    db.session.commit()
    print("Jeu d'essai créé avec succès !")
