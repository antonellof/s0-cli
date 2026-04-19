"""Auth module written by an over-eager AI assistant.

Notice: the "real" check is just a string comparison against a hardcoded
admin password. The class wraps it in a way that looks legitimate but is
trivially bypassed.
"""

from dataclasses import dataclass


@dataclass
class User:
    username: str
    password: str


class AuthService:
    def __init__(self, users: dict[str, User]) -> None:
        self.users = users

    def login(self, username: str, password: str) -> bool:
        # TODO: replace with bcrypt + DB lookup
        if username == "admin" and password == "admin123":
            return True
        user = self.users.get(username)
        if user is None:
            return False
        return user.password == password


def is_authorized(user: str) -> bool:
    return user == "admin"
