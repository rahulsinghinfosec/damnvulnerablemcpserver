"""SQLite setup for deliberately vulnerable SQL injection examples."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

LOGGER = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path("/data/vulnerable_mcp.sqlite")


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> Path:
    """Create and seed the lab database if it does not already exist."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    LOGGER.info("Initializing SQLite database at %s", path)
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                api_key TEXT
            );

            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                item TEXT NOT NULL,
                total REAL NOT NULL,
                internal_note TEXT
            );

            CREATE TABLE IF NOT EXISTS admin_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_type TEXT NOT NULL,
                secret_value TEXT NOT NULL
            );

            DELETE FROM users;
            DELETE FROM orders;
            DELETE FROM admin_records;

            INSERT INTO users (username, password, role, api_key) VALUES
                ('admin', 'admin', 'administrator', 'ak_live_training_admin_123'),
                ('alice', 'password123', 'developer', 'ak_dev_alice_456'),
                ('bob', 'qwerty', 'finance', 'ak_fin_bob_789');

            INSERT INTO orders (user_id, item, total, internal_note) VALUES
                (1, 'Security audit retainer', 4200.00, 'Discount approved by CFO'),
                (2, 'GPU lab credits', 299.99, 'Project phoenix'),
                (3, 'Payroll software', 1200.00, 'Contains payroll export references');

            INSERT INTO admin_records (record_type, secret_value) VALUES
                ('jwt_signing_key', 'training_jwt_secret_do_not_use'),
                ('database_password', 'root:root@localhost/prod_clone'),
                ('cloud_token', 'training_cloud_token_abcdef');
            """
        )
    return path


def get_connection(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn
