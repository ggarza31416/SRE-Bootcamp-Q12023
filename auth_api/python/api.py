from flask import Flask, jsonify, request
from methods import Token, Restricted

app = Flask(__name__)
login = Token()
protected = Restricted()


# Just a health check
@app.route("/")
def url_root():
    return "OK"


# Just a health check
@app.route("/_health")
def url_health():
    return "OK"


# e.g. http://127.0.0.1:8000/login
@app.route("/login", methods=['POST'])
def url_login():
    username = request.form.get('username')
    password = request.form.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400
    token = login.generate_token(username, password)
    if token == 403:
        return jsonify({'error': 'Invalid username or password.'}), 403
    elif token == 500:
        return jsonify({'error': 'Internal Server Error.'}), 500
    return jsonify({'data': token})


# # e.g. http://127.0.0.1:8000/protected
@app.route("/protected")
def url_protected():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Authorization header is missing.'}), 401

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return jsonify({'error': 'Invalid Authorization header.'}), 401

    token = parts[1]
    data = protected.access_data(token)
    if not data:
        return jsonify({'error': 'Invalid or expired token.'}), 401

    return jsonify({'data': data})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
