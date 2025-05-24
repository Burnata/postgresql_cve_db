import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2.extras import DictCursor
from dotenv import load_dotenv
import sys
from functools import wraps # Add this import

# import ssl

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'supersecretkey') # Add a secret key for session management

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('username') != 'Admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# # Route to serve PKI validation file
# @app.route('/.well-known/pki-validation/<filename>')
# def serve_pki_validation_file(filename):
#     return send_from_directory(os.path.join(app.root_path, '.well-known/pki-validation'), filename)

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif password != confirm_password:
            error = 'Passwords do not match.'
        
        if error is None:
            conn = get_connection()
            try:
                with conn.cursor(cursor_factory=DictCursor) as cur:
                    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
                    if cur.fetchone() is not None:
                        error = f"User {username} is already registered."
                    else:
                        hashed_password = generate_password_hash(password)
                        cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                                    (username, hashed_password))
                        conn.commit()
                        flash('Registration successful! Please log in.', 'success')
                        return redirect(url_for('login'))
            except Exception as e:
                app.logger.error(f"Database error during registration: {e}")
                error = "An error occurred during registration. Please try again."
            finally:
                if conn:
                    conn.close()
        
        if error:
            flash(error, 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None
        conn = get_connection()
        try:
            with conn.cursor(cursor_factory=DictCursor) as cur:
                cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cur.fetchone()

            if user is None:
                error = 'Incorrect username.'
            elif not check_password_hash(user['password_hash'], password):
                error = 'Incorrect password.'

            if error is None:
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
        except Exception as e:
            app.logger.error(f"Database error during login: {e}")
            error = "An error occurred during login. Please try again."
        finally:
            if conn:
                conn.close()
        
        if error:
            flash(error, 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/admin')
@admin_required
def admin_panel():
    conn = get_connection()
    users = []
    try:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            # Fetch all users except the Admin user itself
            cur.execute("SELECT id, username FROM users WHERE username != 'Admin' ORDER BY username")
            users = cur.fetchall()
    except Exception as e:
        app.logger.error(f"Database error fetching users for admin panel: {e}")
        flash("Error fetching user list.", "danger")
    finally:
        if conn:
            conn.close()
    return render_template('admin_panel.html', users=users)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s AND username != 'Admin'", (user_id,))
            conn.commit()
            if cur.rowcount > 0:
                flash('User deleted successfully.', 'success')
            else:
                flash('User not found or cannot be deleted.', 'warning')
    except Exception as e:
        app.logger.error(f"Database error deleting user: {e}")
        flash('Error deleting user.', 'danger')
    finally:
        if conn:
            conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    conn = get_connection()
    user = None
    try:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute("SELECT id, username FROM users WHERE id = %s AND username != 'Admin'", (user_id,))
            user = cur.fetchone()
        
        if not user:
            flash('User not found or cannot be edited.', 'warning')
            return redirect(url_for('admin_panel'))

        if request.method == 'POST':
            new_password = request.form['password']
            confirm_password = request.form['confirm_password']

            if not new_password:
                flash('New password cannot be empty.', 'danger')
            elif new_password != confirm_password:
                flash('Passwords do not match.', 'danger')
            else:
                hashed_password = generate_password_hash(new_password)
                try: # New try block for update
                    with conn.cursor() as cur_update: # New cursor for update
                        cur_update.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed_password, user_id))
                        conn.commit()
                    flash('Password updated successfully.', 'success')
                    return redirect(url_for('admin_panel'))
                except Exception as e_update:
                    app.logger.error(f"Database error updating password: {e_update}")
                    flash('Error updating password.', 'danger')
    finally: # Ensure connection is closed if opened
        if conn and request.method == 'GET': # Only close if GET, POST will close after update or error
             conn.close()
        elif conn and request.method == 'POST' and not 'cur_update' in locals() : # if POST failed before update cursor
             conn.close()


    # If GET request or POST failed before redirect, render the edit page
    # The connection might have been closed by the finally block if it was a GET or early POST error
    # Re-fetch user if connection was closed and it's a GET request or POST had an error before update
    if not user and conn.closed: # Simplified check
        conn = get_connection() # Reopen if closed
        try:
            with conn.cursor(cursor_factory=DictCursor) as cur_refetch:
                cur_refetch.execute("SELECT id, username FROM users WHERE id = %s AND username != 'Admin'", (user_id,))
                user = cur_refetch.fetchone()
        except Exception as e_refetch:
            app.logger.error(f"Database error re-fetching user for edit: {e_refetch}")
            flash("Error loading user details for editing.", "danger")
            return redirect(url_for('admin_panel')) # Redirect if re-fetch fails
        finally:
            if conn and not conn.closed: # Close if re-opened
                conn.close()
    
    if not user: # If user still not found after potential re-fetch
        flash('User not found or cannot be edited.', 'warning')
        return redirect(url_for('admin_panel'))
        
    return render_template('admin_edit_user.html', user=user)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)