import os
from flask import Flask, render_template, request, redirect, url_for
import psycopg2
from psycopg2.extras import DictCursor
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "mydatabase"),
        user=os.getenv("DB_USER", "myuser"),
        password=os.getenv("DB_PASSWORD", "mypassword")
    )

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
        print(f"Database error: {e}")
        cves = []
        vendors = []
        total_pages = 1
    finally:
        conn.close()
    
    return render_template(
        'index.html', 
        cves=cves, 
        vendors=vendors,
        vendor=vendor,
        has_exploit=has_exploit,
        has_fix=has_fix,
        page=page,
        total_pages=total_pages
    )

@app.route('/cve/<cve_id>')
def cve_detail(cve_id):
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
        print(f"Database error: {e}")
        cve = None
        vendors = []
    finally:
        conn.close()
    
    if not cve:
        return redirect(url_for('index'))
    
    return render_template('detail.html', cve=cve, vendors=vendors)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)