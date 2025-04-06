import sqlite3

# Chemin vers ta base de données
db_path = "instance/tickets.db"

# Connexion à la base
conn = sqlite3.connect(db_path)
cursor = conn.cursor()


# Récupération des noms de toutes les tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

print("📦 Tables trouvées dans la base :\n")
for table in tables:
    table_name = table[0]
    print(f"🧾 Table : {table_name}")

    # Récupérer les colonnes
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [info[1] for info in cursor.fetchall()]
    print(f"   Colonnes : {', '.join(columns)}")

    # Afficher les données
    cursor.execute(f"SELECT * FROM {table_name}")
    rows = cursor.fetchall()
    if rows:
        for row in rows:
            print("   ", dict(zip(columns, row)))
    else:
        print("   (aucune donnée)")
    print()

conn.close()
