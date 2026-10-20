import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from app import create_app, provision_user


@pytest.fixture
def setup(tmp_path):
    secret = secrets.token_hex(32)
    app = create_app({'TESTING': True, 'DATABASE': str(tmp_path / 'test.sqlite3'),
                      'JWT_SECRET': secret})
    password = secrets.token_urlsafe(24)
    provision_user(app, 'alice', password)
    provision_user(app, 'bob', secrets.token_urlsafe(24))
    return app, app.test_client(), password, secret


def token(client, password):
    response = client.post('/auth/login', json={'login': 'alice', 'password': password})
    assert response.status_code == 200
    return response.json['access_token']


def test_authentication_and_owner_isolation(setup):
    app, client, password, _ = setup
    bearer = token(client, password)
    headers = {'Authorization': 'Bearer ' + bearer}
    assert client.get('/api/data').status_code == 401
    assert client.post('/api/notes', json={'body': 'x'}).status_code == 401
    assert client.post('/api/notes', json={'body': 'my note'}, headers=headers).status_code == 201
    with sqlite3.connect(app.config['DATABASE']) as conn:
        conn.execute('INSERT INTO notes(owner, body) VALUES (?, ?)', (2, 'Bobs private note'))
    response = client.get('/api/data', headers=headers)
    assert response.status_code == 200
    assert [n['body'] for n in response.json['notes']] == ['my note']


@pytest.mark.parametrize('login', ["alice\' OR 1=1 --", "\' UNION SELECT 1 --", 'missing'])
def test_sqli_and_invalid_login(setup, login):
    _, client, password, _ = setup
    assert client.post('/auth/login', json={'login': login, 'password': password}).status_code == 401


def test_xss_escaped_and_json_headers(setup):
    _, client, password, _ = setup
    headers = {'Authorization': 'Bearer ' + token(client, password)}
    payload = '<img src=x onerror=alert(1)>'
    created = client.post('/api/notes', json={'body': payload}, headers=headers)
    assert created.status_code == 201
    assert created.json['body'] == '&lt;img src=x onerror=alert(1)&gt;'
    response = client.get('/api/data', headers=headers)
    assert '<img' not in response.get_data(as_text=True)
    assert response.mimetype == 'application/json'
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['Cache-Control'] == 'no-store'


@pytest.mark.parametrize('kind', ['expired', 'wrong-key', 'wrong-audience', 'missing-exp', 'none'])
def test_jwt_rejection(setup, kind):
    _, client, _, secret = setup
    now = datetime.now(timezone.utc)
    claims = {'sub': '1', 'iat': now, 'exp': now + timedelta(minutes=15),
              'iss': 'hdu-course-api', 'aud': 'hdu-course-client'}
    if kind == 'expired':
        claims['exp'] = now - timedelta(seconds=5)
    if kind == 'wrong-audience':
        claims['aud'] = 'other'
    if kind == 'missing-exp':
        del claims['exp']
    value = jwt.encode(claims, '' if kind == 'none' else (secrets.token_hex(32) if kind == 'wrong-key' else secret),
                       algorithm='none' if kind == 'none' else 'HS256')
    assert client.get('/api/data', headers={'Authorization': 'Bearer ' + value}).status_code == 401


def test_input_limits_and_hash_storage(setup):
    app, client, password, _ = setup
    headers = {'Authorization': 'Bearer ' + token(client, password)}
    for body in ['', 'x' * 501, 5, None]:
        assert client.post('/api/notes', json={'body': body}, headers=headers).status_code == 400
    assert client.post('/auth/login', json=[]).status_code == 400
    assert client.post('/auth/login', json={'login': 'alice', 'password': 1}).status_code == 400
    with sqlite3.connect(app.config['DATABASE']) as conn:
        stored = conn.execute('SELECT password_hash FROM users WHERE login = ?', ('alice',)).fetchone()[0]
    assert stored.startswith('scrypt:') and stored != password


def test_secret_required(tmp_path):
    with pytest.raises(RuntimeError):
        create_app({'DATABASE': str(tmp_path/'other.sqlite3'), 'JWT_SECRET': None})
