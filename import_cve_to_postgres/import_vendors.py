import os
import json
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def get_connection():
    return psycopg2.connect(
        host="localhost",
        port="5432",
        dbname="mydatabase",
        user="myuser",
        password="mypassword"
    )

def create_vendors_table(conn):
    with conn.cursor() as cur:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS vendors (
                id SERIAL PRIMARY KEY,
                cve_id TEXT NOT NULL,
                vendor_name TEXT NOT NULL,
                FOREIGN KEY (cve_id) REFERENCES cve_simple(cve_id) ON DELETE CASCADE
            )
        ''')
        conn.commit()

def extract_vendors(json_data):
    cve_id = json_data.get('cveMetadata', {}).get('cveId')
    affected = json_data.get('containers', {}).get('cna', {}).get('affected', [])
    vendors = set()
    for item in affected:
        vendor = item.get('vendor')
        if vendor:
            vendors.add(vendor)
    return [(cve_id, vendor) for vendor in vendors if cve_id]

def process_all_files(base_path, conn):
    to_insert = []
    for root, dirs, files in os.walk(base_path):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, encoding='utf-8') as f:
                        data = json.load(f)
                        rows = extract_vendors(data)
                        to_insert.extend(rows)
                except Exception as e:
                    print(f"Error processing {file_path}: {e}")
    if to_insert:
        with conn.cursor() as cur:
            execute_values(cur, """
                INSERT INTO vendors (cve_id, vendor_name)
                VALUES %s
                ON CONFLICT DO NOTHING
            """, to_insert)
        conn.commit()

if __name__ == "__main__":
    cve_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'cves')
    conn = get_connection()
    create_vendors_table(conn)
    process_all_files(cve_dir, conn)
    conn.close()
    print("Vendors import complete.")
