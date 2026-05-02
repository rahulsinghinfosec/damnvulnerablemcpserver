"""Mock sensitive data exposed by intentionally vulnerable tools."""

MOCK_NOTES = [
    {
        "id": 1,
        "title": "Incident response note",
        "body": "Rotate the staging API key after Friday's demo.",
    },
    {
        "id": 2,
        "title": "Payroll export",
        "body": "Temporary payroll export lives in /lab-data/payroll.csv.",
    },
    {
        "id": 3,
        "title": "Cloud migration",
        "body": "Metadata service should not be reachable from app containers.",
    },
]

MOCK_USERS = [
    {"id": 1, "username": "admin", "role": "administrator", "email": "admin@example.local"},
    {"id": 2, "username": "alice", "role": "developer", "email": "alice@example.local"},
    {"id": 3, "username": "bob", "role": "finance", "email": "bob@example.local"},
]

MOCK_ADMIN_LOGS = [
    "2026-05-01T09:10:03Z admin exported all customer records",
    "2026-05-01T10:44:21Z secret_key=lab_sk_12345_insecure_training_secret",
    "2026-05-01T12:01:00Z root shell opened inside container for debugging",
]
