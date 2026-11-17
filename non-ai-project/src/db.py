"""
Database access layer using standard connection pooling.
All queries strictly parameterized.
"""

import os

def get_db_connection_params():
    return {
        "host": os.environ.get("DB_HOST", "localhost"),
        "port": int(os.environ.get("DB_PORT", "5432")),
        "database": os.environ.get("DB_NAME", "orders_prod"),
        "user": os.environ.get("DB_USER", "app_service"),
        "ssl_mode": "require",
    }

def record_order(cursor, order_id: str, customer_id: str, total_amount: float):
    # Parameterized SQL query - safe against injection
    sql = "INSERT INTO orders (id, customer_id, total, status) VALUES (%s, %s, %s, %s)"
    cursor.execute(sql, (order_id, customer_id, total_amount, "CONFIRMED"))
