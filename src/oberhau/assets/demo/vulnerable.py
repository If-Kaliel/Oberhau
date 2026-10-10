"""LABORATORY MATERIAL ONLY. Never deploy or execute this imported fixture."""

import os
import pickle

DEBUG = True
api_key = "oberhau_fake_fixture_credential_123456"


def calculate(user_input):
    return eval(user_input)


def command(user_input):
    os.system(user_input)


def deserialize(user_input):
    return pickle.loads(user_input)


def lookup(connection, user_input):
    return connection.execute(f"SELECT name FROM users WHERE name = '{user_input}'").fetchall()


def record_without_authorization(database, record_id):
    # Missing authorization is an investigation exercise, not automatically confirmed by this scanner.
    return database[record_id]
