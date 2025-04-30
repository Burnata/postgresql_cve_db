import os
import json
import re
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

# Create table if not exists
def create_table(conn):
    with conn.cursor() as cur:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS cve_simple (
                id SERIAL PRIMARY KEY,
                cve_id TEXT NOT NULL UNIQUE,
                affected_package TEXT NOT NULL,
                score REAL
            )
        ''')
        conn.commit()

# Extract cve_id, affected_package, score from a CVE JSON file
def extract_cve_info(json_data):
    if not isinstance(json_data, dict):
        return []
    cve_id = json_data.get('cveMetadata', {}).get('cveId')
    affected = json_data.get('containers', {}).get('cna', {}).get('affected', [])
    metrics = json_data.get('containers', {}).get('cna', {}).get('metrics', {})
    descriptions = json_data.get('containers', {}).get('cna', {}).get('descriptions', [])
    score = None
    # Handle metrics as dict or list
    if isinstance(metrics, dict):
        for key in ['cvssV3_1', 'cvssV3_0', 'cvssV2_0']:
            for metric in metrics.get(key, []):
                if isinstance(metric, dict) and 'baseScore' in metric:
                    score = metric['baseScore']
                    break
            if score is not None:
                break
    elif isinstance(metrics, list):
        for metric_obj in metrics:
            for key in ['cvssV3_1', 'cvssV3_0', 'cvssV2_0']:
                metric = metric_obj.get(key)
                if metric and 'baseScore' in metric:
                    score = metric['baseScore']
                    break
            if score is not None:
                break
    # Try to extract package name from description if product is 'n/a'
    def guess_package():
        for desc in descriptions:
            value = desc.get('value', '')
            m = re.search(r'The ([\w:.:\-]+) package', value)
            if m:
                return m.group(1)
            m = re.search(r'([\w:.:\-]+) for [A-Za-z]+', value)
            if m:
                return m.group(1)
        return None
    results = []
    for item in affected:
        product = item.get('product')
        if product and product.lower() == 'n/a':
            product = guess_package() or 'n/a'
        if cve_id and product:
            results.append((cve_id, product, score))
    return results

# Recursively walk through cvelistV5/cves and process JSON files
def process_all_files(base_path, conn):
    to_insert = []
    for root, dirs, files in os.walk(base_path):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, encoding='utf-8') as f:
                        data = json.load(f)
                        rows = extract_cve_info(data)
                        to_insert.extend(rows)
                except Exception as e:
                    print(f"Error processing {file_path}: {e}")
    # Bulk insert
    if to_insert:
        with conn.cursor() as cur:
            execute_values(cur, """
                INSERT INTO cve_simple (cve_id, affected_package, score)
                VALUES %s
                ON CONFLICT DO NOTHING
            """, to_insert)
        conn.commit()

if __name__ == "__main__":
    import sys
    # Allow processing by year: python import_cve_simple.py 2002
    if len(sys.argv) > 1:
        year = sys.argv[1]
        cve_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'cves', year)
    else:
        cve_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'cves')
    conn = get_connection()
    create_table(conn)
    process_all_files(cve_dir, conn)
    conn.close()
    print("Import complete.")
