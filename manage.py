"""Provision a local synthetic user without echoing their password."""
from getpass import getpass
from app import create_app, provision_user

if __name__ == '__main__':
    login = input('Synthetic login: ').strip()
    password = getpass('Synthetic password (not a real account password): ')
    if not login or len(login) > 100 or len(password) < 12:
        raise SystemExit('Use a non-empty login up to 100 characters and a password of at least 12 characters')
    provision_user(create_app(), login, password)
    print('Synthetic user created. No password has been printed.')
