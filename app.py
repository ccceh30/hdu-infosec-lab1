"""Course API: all non-login endpoints require a verified, short-lived JWT."""
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import jwt
from flask import Flask, g, jsonify, request
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

HTTP_AUTH_SCHEME = 'Bearer'  # Public protocol label, never a credential.

def create_app(config=None):
    app = Flask(__name__)
    app.config.update(DATABASE=os.environ.get('API_DATABASE', 'course.sqlite3'),
                      JWT_SECRET=os.environ.get('API_JWT_SECRET'),
                      MAX_CONTENT_LENGTH=8192)
    if config:
        app.config.update(config)
    secret = app.config['JWT_SECRET']
    if not isinstance(secret, str) or len(secret) < 32:
        raise RuntimeError('Set API_JWT_SECRET to an independent random secret of at least 32 characters')

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(app.config['DATABASE'])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        conn = g.pop('db', None)
        if conn is not None:
            conn.close()

    with app.app_context():
        db().executescript('''CREATE TABLE IF NOT EXISTS users
            (id INTEGER PRIMARY KEY, login TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS notes
            (id INTEGER PRIMARY KEY, owner INTEGER NOT NULL, body TEXT NOT NULL);''')
        db().commit()

    def protected(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            authorization = request.headers.get('Authorization', '')
            if not authorization.startswith('Bearer '):
                return jsonify(error='Authentication required'), 401
            try:
                claims = jwt.decode(authorization[7:], secret, algorithms=['HS256'],
                                    issuer='hdu-course-api', audience='hdu-course-client',
                                    options={'require': ['exp', 'iat', 'sub', 'iss', 'aud']})
                user = db().execute('SELECT id, login FROM users WHERE id = ?',
                                    (int(claims['sub']),)).fetchone()
                if user is None:
                    raise ValueError('Unknown subject')
                g.user = user
            except (jwt.InvalidTokenError, ValueError, TypeError):
                return jsonify(error='Invalid or expired token'), 401
            return fn(*args, **kwargs)
        return wrapped

    @app.after_request
    def security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.post('/auth/login')
    def login():
        value = request.get_json(silent=True)
        if not isinstance(value, dict):
            return jsonify(error='JSON object required'), 400
        login_name, password = value.get('login'), value.get('password')
        if not isinstance(login_name, str) or not isinstance(password, str):
            return jsonify(error='login and password must be strings'), 400
        if len(login_name) > 100 or len(password) > 1024:
            return jsonify(error='Input too long'), 400
        user = db().execute('SELECT * FROM users WHERE login = ?', (login_name,)).fetchone()
        # Constant-cost dummy check avoids skipping the expensive hash for unknown users.
        stored = user['password_hash'] if user else app.config['DUMMY_HASH']
        valid = check_password_hash(stored, password)
        if user is None or not valid:
            return jsonify(error='Invalid credentials'), 401
        now = datetime.now(timezone.utc)
        token = jwt.encode({'sub': str(user['id']), 'iat': now,
                            'exp': now + timedelta(minutes=15),
                            'iss': 'hdu-course-api', 'aud': 'hdu-course-client'},
                           secret, algorithm='HS256')
        return jsonify({'access_token': token, 'token_type': HTTP_AUTH_SCHEME, 'expires_in': 900})

    @app.get('/api/data')
    @protected
    def data():
        rows = db().execute('SELECT id, body FROM notes WHERE owner = ? ORDER BY id',
                            (g.user['id'],)).fetchall()
        return jsonify(notes=[{'id': row['id'], 'body': str(escape(row['body']))} for row in rows])

    @app.post('/api/notes')
    @protected
    def add_note():
        value = request.get_json(silent=True)
        body = value.get('body') if isinstance(value, dict) else None
        if not isinstance(body, str) or not 1 <= len(body) <= 500:
            return jsonify(error='body must contain 1-500 characters'), 400
        cursor = db().execute('INSERT INTO notes(owner, body) VALUES (?, ?)',
                              (g.user['id'], body))
        db().commit()
        return jsonify(id=cursor.lastrowid, body=str(escape(body))), 201

    app.config['DUMMY_HASH'] = generate_password_hash(os.urandom(24).hex(), method='scrypt')
    return app


def provision_user(app, login_name, password):
    """Local administrator helper. No public registration or password disclosure."""
    conn = sqlite3.connect(app.config['DATABASE'])
    try:
        conn.execute('INSERT INTO users(login, password_hash) VALUES (?, ?)',
                     (login_name, generate_password_hash(password, method='scrypt')))
        conn.commit()
    finally:
        conn.close()


if __name__ == '__main__':
    application = create_app()
    application.run(host='127.0.0.1', port=5055, debug=False)
