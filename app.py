from flask import Flask, render_template, request
# from errors import page_not_found, internal_server_error  # Import des erreurs

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html', message="Bienvenue sur Flask !")

if __name__ == '__main__':
    app.run(debug=True)