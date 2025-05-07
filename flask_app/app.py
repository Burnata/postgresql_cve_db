import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import psycopg2
from psycopg2.extras import DictCursor
from dotenv import load_dotenv
import sys
import ssl

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Route to serve PKI validation file
@app.route('/.well-known/pki-validation/<filename>')
def serve_pki_validation_file(filename):
    return send_from_directory(os.path.join(app.root_path, '.well-known/pki-validation'), filename)

def get_connection():
    try:
        print(f"Attempting to connect to database: host={os.getenv('DB_HOST', 'localhost')}, port={os.getenv('DB_PORT', '5432')}, dbname={os.getenv('DB_NAME', 'mydatabase')}")
        return psycopg2.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", "5432"),
            dbname=os.getenv("DB_NAME", "mydatabase"),
            user=os.getenv("DB_USER", "myuser"),
            password=os.getenv("DB_PASSWORD", "mypassword")
        )
    except Exception as e:
        print(f"Database connection error: {e}", file=sys.stderr)
        raise

@app.route('/')
def index():
    # Query parameters for filtering
    vendor = request.args.get('vendor', '')
    has_exploit = request.args.get('has_exploit', '')
    has_fix = request.args.get('has_fix', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    # Build the query based on filters
    query = """
        SELECT cs.cve_id, cs.affected_package, cs.score, 
               ces.has_active_exploit, cfs.has_fix, 
               string_agg(DISTINCT v.vendor_name, ', ') as vendors
        FROM cve_simple cs
        LEFT JOIN cve_exploit_status ces ON cs.cve_id = ces.cve_id
        LEFT JOIN cve_fix_status cfs ON cs.cve_id = cfs.cve_id
        LEFT JOIN vendors v ON cs.cve_id = v.cve_id
        WHERE 1=1
    """
    
    params = []
    if vendor:
        query += " AND v.vendor_name ILIKE %s"
        params.append(f'%{vendor}%')
    
    if has_exploit:
        has_exploit_bool = has_exploit.lower() == 'true'
        query += " AND ces.has_active_exploit = %s"
        params.append(has_exploit_bool)
    
    if has_fix:
        has_fix_bool = has_fix.lower() == 'true'
        query += " AND cfs.has_fix = %s"
        params.append(has_fix_bool)
    
    query += " GROUP BY cs.cve_id, cs.affected_package, cs.score, ces.has_active_exploit, cfs.has_fix"
    query += " ORDER BY cs.cve_id"
    query += " LIMIT %s OFFSET %s"
    params.extend([per_page, offset])
    
    # Count total matching records for pagination
    count_query = """
        SELECT COUNT(DISTINCT cs.cve_id)
        FROM cve_simple cs
        LEFT JOIN cve_exploit_status ces ON cs.cve_id = ces.cve_id
        LEFT JOIN cve_fix_status cfs ON cs.cve_id = cfs.cve_id
        LEFT JOIN vendors v ON cs.cve_id = v.cve_id
        WHERE 1=1
    """
    
    count_params = []
    if vendor:
        count_query += " AND v.vendor_name ILIKE %s"
        count_params.append(f'%{vendor}%')
    
    if has_exploit:
        has_exploit_bool = has_exploit.lower() == 'true'
        count_query += " AND ces.has_active_exploit = %s"
        count_params.append(has_exploit_bool)
    
    if has_fix:
        has_fix_bool = has_fix.lower() == 'true'
        count_query += " AND cfs.has_fix = %s"
        count_params.append(has_fix_bool)
    
    cves = []
    vendors = []
    total_pages = 1
    error_message = None
    
    try:
        conn = get_connection()
        try:
            with conn.cursor(cursor_factory=DictCursor) as cur:
                # Get total count for pagination
                cur.execute(count_query, count_params)
                total_count = cur.fetchone()[0]
                total_pages = (total_count + per_page - 1) // per_page
                
                # Get CVE records
                cur.execute(query, params)
                cves = cur.fetchall()
                
                # Get vendors for filter dropdown
                cur.execute("""
                    SELECT DISTINCT vendor_name 
                    FROM vendors 
                    ORDER BY vendor_name
                """)
                vendors = [row[0] for row in cur.fetchall()]
        except Exception as e:
            app.logger.error(f"Database query error: {e}")
            error_message = f"Error executing database query: {e}"
        finally:
            conn.close()
    except Exception as e:
        app.logger.error(f"Database connection error: {e}")
        error_message = "Unable to connect to the database. Please try again later."
    
    return render_template(
        'index.html', 
        cves=cves, 
        vendors=vendors,
        vendor=vendor,
        has_exploit=has_exploit,
        has_fix=has_fix,
        page=page,
        total_pages=total_pages,
        error_message=error_message
    )

@app.route('/cve/<cve_id>')
def cve_detail(cve_id):
    cve = None
    vendors = []
    error_message = None
    
    try:
        conn = get_connection()
        try:
            with conn.cursor(cursor_factory=DictCursor) as cur:
                # Get CVE basic info
                cur.execute("""
                    SELECT cs.cve_id, cs.affected_package, cs.score, 
                           ces.has_active_exploit, cfs.has_fix
                    FROM cve_simple cs
                    LEFT JOIN cve_exploit_status ces ON cs.cve_id = ces.cve_id
                    LEFT JOIN cve_fix_status cfs ON cs.cve_id = cfs.cve_id
                    WHERE cs.cve_id = %s
                """, (cve_id,))
                cve = cur.fetchone()
                
                # Get vendors for this CVE
                cur.execute("""
                    SELECT vendor_name
                    FROM vendors
                    WHERE cve_id = %s
                """, (cve_id,))
                vendors = [row[0] for row in cur.fetchall()]
        except Exception as e:
            app.logger.error(f"Database query error: {e}")
            error_message = f"Error executing database query: {e}"
        finally:
            conn.close()
    except Exception as e:
        app.logger.error(f"Database connection error: {e}")
        error_message = "Unable to connect to the database. Please try again later."
    
    if not cve and not error_message:
        return redirect(url_for('index'))
    
    return render_template('detail.html', cve=cve, vendors=vendors, error_message=error_message)

@app.route('/schema')
def db_schema():
    """Display the database schema and relationships."""
    error_message = None
    tables = []
    relationships = []
    
    try:
        conn = get_connection()
        try:
            with conn.cursor(cursor_factory=DictCursor) as cur:
                # Get table information
                tables_query = """
                    SELECT 
                        table_name, 
                        (SELECT string_agg(column_name || ' (' || data_type || ')', ', ')
                         FROM information_schema.columns
                         WHERE table_name = t.table_name
                         AND table_schema = 'public'
                        ) as columns
                    FROM information_schema.tables t
                    WHERE table_schema = 'public'
                    AND table_type = 'BASE TABLE'
                    AND table_name IN ('cve_simple', 'cve_exploit_status', 'cve_fix_status', 'vendors')
                """
                cur.execute(tables_query)
                for row in cur.fetchall():
                    tables.append({
                        'name': row['table_name'],
                        'columns': row['columns']
                    })
                
                # Get foreign key relationships
                relationships_query = """
                    SELECT
                        tc.table_name as table_name,
                        kcu.column_name as column_name,
                        ccu.table_name as referenced_table,
                        ccu.column_name as referenced_column
                    FROM
                        information_schema.table_constraints AS tc
                        JOIN information_schema.key_column_usage AS kcu
                          ON tc.constraint_name = kcu.constraint_name
                          AND tc.table_schema = kcu.table_schema
                        JOIN information_schema.constraint_column_usage AS ccu
                          ON ccu.constraint_name = tc.constraint_name
                          AND ccu.table_schema = tc.table_schema
                    WHERE tc.constraint_type = 'FOREIGN KEY'
                    AND tc.table_schema = 'public'
                """
                cur.execute(relationships_query)
                relationships = cur.fetchall()
                
                # Get table row counts
                tables_with_counts = []
                for table in tables:
                    count_query = f"SELECT COUNT(*) as count FROM {table['name']}"
                    cur.execute(count_query)
                    count = cur.fetchone()['count']
                    tables_with_counts.append({
                        'name': table['name'],
                        'columns': table['columns'],
                        'row_count': count
                    })
                tables = tables_with_counts
                
        except Exception as e:
            app.logger.error(f"Database query error: {e}")
            error_message = f"Error executing database query: {e}"
        finally:
            conn.close()
    except Exception as e:
        app.logger.error(f"Database connection error: {e}")
        error_message = "Unable to connect to the database. Please try again later."
    
    return render_template('schema.html', tables=tables, relationships=relationships, error_message=error_message)

if __name__ == '__main__':
    ssl_context = None
    cert_path = os.getenv('SSL_CERT_PATH')
    key_path = os.getenv('SSL_KEY_PATH')
    
    if cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path):
        # Create SSL context with TLS 1.3
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(cert_path, key_path)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        
        app.run(host='0.0.0.0', port=5000, debug=True, ssl_context=ssl_context)
    else:
        app.run(host='0.0.0.0', port=5000, debug=True)