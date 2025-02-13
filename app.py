from flask import Flask, render_template, request
# from errors import page_not_found, internal_server_error  # Import des erreurs

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html', message="Bienvenue sur Flask !")

@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template("500.html"), 500

if __name__ == '__main__':
    app.run(debug=True)