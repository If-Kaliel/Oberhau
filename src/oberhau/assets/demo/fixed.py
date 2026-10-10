"""LABORATORY CONTROL: corrected query, bounded arithmetic, explicit access check."""

DEBUG = False


def lookup(connection, user_input):
    return connection.execute("SELECT name FROM users WHERE name = ?", (user_input,)).fetchall()


def calculate(left: int, right: int):
    return left + right


def record_with_authorization(database, record_id, owner):
    record = database[record_id]
    if record["owner"] != owner:
        raise PermissionError("Unauthorized record")
    return record
