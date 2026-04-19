"""Application config with a hardcoded API key."""

DATABASE_URL = "postgresql://app:app@localhost/app"

STRIPE_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc1234567890ABCD"

DEBUG = False


def get_database_url() -> str:
    return DATABASE_URL
