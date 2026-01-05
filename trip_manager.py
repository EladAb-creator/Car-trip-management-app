from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import sqlite3
import os
import hashlib
from datetime import datetime
from functools import wraps
from contextlib import closing

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24).hex())
DATABASE = 'trip_manager.db'

def get_db():
    """Get database connection"""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize database with tables"""
    with closing(get_db()) as db:
        # Drivers table
        db.execute('''
            CREATE TABLE IF NOT EXISTS drivers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_refueler INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Trips table
        db.execute('''
            CREATE TABLE IF NOT EXISTS trips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                km REAL NOT NULL,
                date TEXT NOT NULL,
                FOREIGN KEY (username) REFERENCES drivers(username)
            )
        ''')
        
        # Refuelings table
        db.execute('''
            CREATE TABLE IF NOT EXISTS refuelings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cost REAL NOT NULL,
                date TEXT NOT NULL,
                added_by TEXT NOT NULL,
                FOREIGN KEY (added_by) REFERENCES drivers(username)
            )
        ''')
        
        db.commit()

def hash_password(password):
    """Hash a password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        with closing(get_db()) as db:
            user = db.execute(
                'SELECT is_admin FROM drivers WHERE username = ?',
                (session['username'],)
            ).fetchone()
            if not user or not user['is_admin']:
                flash('רק מנהל יכול לגשת לדף זה', 'error')
                return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def refueler_required(f):
    """Decorator to require refueler role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        with closing(get_db()) as db:
            user = db.execute(
                'SELECT is_refueler FROM drivers WHERE username = ?',
                (session['username'],)
            ).fetchone()
            if not user or not user['is_refueler']:
                flash('רק מי שמתדלק יכול לבצע פעולה זו', 'error')
                return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('יש למלא את כל השדות', 'error')
            return render_template('login.html')
        
        password_hash = hash_password(password)
        
        with closing(get_db()) as db:
            user = db.execute(
                'SELECT username, is_refueler, is_admin FROM drivers WHERE username = ? AND password_hash = ?',
                (username, password_hash)
            ).fetchone()
            
            if user:
                session['username'] = user['username']
                session['is_refueler'] = bool(user['is_refueler'])
                session['is_admin'] = bool(user['is_admin'])
                flash('התחברת בהצלחה!', 'success')
                return redirect(url_for('index'))
            else:
                flash('שם משתמש או סיסמה שגויים', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        is_refueler = request.form.get('is_refueler') == 'on'
        
        if not username or not password:
            flash('יש למלא את כל השדות', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('הסיסמאות לא תואמות', 'error')
            return render_template('register.html')
        
        if len(password) < 4:
            flash('הסיסמה חייבת להכיל לפחות 4 תווים', 'error')
            return render_template('register.html')
        
        password_hash = hash_password(password)
        
        with closing(get_db()) as db:
            try:
                db.execute(
                    'INSERT INTO drivers (username, password_hash, is_refueler, created_at) VALUES (?, ?, ?, ?)',
                    (username, password_hash, 1 if is_refueler else 0, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                )
                db.commit()
                flash('נרשמת בהצלחה! כעת תוכל להתחבר', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('שם משתמש כבר קיים', 'error')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    flash('התנתקת בהצלחה', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Main dashboard page"""
    username = session['username']
    is_refueler = session.get('is_refueler', False)
    
    with closing(get_db()) as db:
        # Get user's trips
        user_trips = db.execute(
            'SELECT * FROM trips WHERE username = ? ORDER BY date DESC',
            (username,)
        ).fetchall()
        user_total_km = sum(trip['km'] for trip in user_trips)
        
        # Get all trips for statistics
        all_trips = db.execute('SELECT * FROM trips').fetchall()
        total_km = sum(trip['km'] for trip in all_trips)
        
        # Calculate km per user
        user_km = {}
        for trip in all_trips:
            user = trip['username']
            user_km[user] = user_km.get(user, 0) + trip['km']
        
        # Get all refuelings
        refuelings = db.execute('SELECT * FROM refuelings ORDER BY date DESC').fetchall()
        total_refueling_cost = sum(ref['cost'] for ref in refuelings)
        
        # Calculate payments
        user_payments = {}
        if total_km > 0:
            for user, km in user_km.items():
                user_payments[user] = (km / total_km) * total_refueling_cost
    
    return render_template('index.html', 
                         username=username,
                         is_refueler=is_refueler,
                         is_admin=session.get('is_admin', False),
                         user_trips=user_trips,
                         user_total_km=user_total_km,
                         refuelings=refuelings,
                         user_km=user_km,
                         total_km=total_km,
                         total_refueling_cost=total_refueling_cost,
                         user_payments=user_payments)

@app.route('/add_trip', methods=['POST'])
@login_required
def add_trip():
    """Add a new trip - only for logged-in user"""
    username = session['username']
    km = request.form.get('km', '').strip()
    
    if not km:
        flash('יש למלא את הקילומטראז\'', 'error')
        return redirect(url_for('index'))
    
    try:
        km_float = float(km)
        if km_float <= 0:
            flash('קילומטראז\' חייב להיות חיובי', 'error')
            return redirect(url_for('index'))
    except ValueError:
        flash('קילומטראז\' חייב להיות מספר', 'error')
        return redirect(url_for('index'))
    
    with closing(get_db()) as db:
        db.execute(
            'INSERT INTO trips (username, km, date) VALUES (?, ?, ?)',
            (username, km_float, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
        db.commit()
    
    flash('נסיעה נוספה בהצלחה!', 'success')
    return redirect(url_for('index'))

@app.route('/add_refueling', methods=['POST'])
@refueler_required
def add_refueling():
    """Add a new refueling record - only for refuelers"""
    cost = request.form.get('cost', '').strip()
    
    if not cost:
        flash('יש למלא את עלות התדלוק', 'error')
        return redirect(url_for('index'))
    
    try:
        cost_float = float(cost)
        if cost_float <= 0:
            flash('עלות התדלוק חייבת להיות חיובית', 'error')
            return redirect(url_for('index'))
    except ValueError:
        flash('עלות התדלוק חייבת להיות מספר', 'error')
        return redirect(url_for('index'))
    
    with closing(get_db()) as db:
        db.execute(
            'INSERT INTO refuelings (cost, date, added_by) VALUES (?, ?, ?)',
            (cost_float, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), session['username'])
        )
        db.commit()
    
    flash('תדלוק נוסף בהצלחה!', 'success')
    return redirect(url_for('index'))

@app.route('/delete_trip/<int:trip_id>', methods=['POST'])
@login_required
def delete_trip(trip_id):
    """Delete a trip - only if it belongs to the logged-in user"""
    username = session['username']
    
    with closing(get_db()) as db:
        # Check if trip belongs to user
        trip = db.execute(
            'SELECT id FROM trips WHERE id = ? AND username = ?',
            (trip_id, username)
        ).fetchone()
        
        if trip:
            db.execute('DELETE FROM trips WHERE id = ?', (trip_id,))
            db.commit()
            flash('נסיעה נמחקה בהצלחה', 'success')
        else:
            flash('לא ניתן למחוק נסיעה זו', 'error')
    
    return redirect(url_for('index'))

@app.route('/delete_refueling/<int:refueling_id>', methods=['POST'])
@refueler_required
def delete_refueling(refueling_id):
    """Delete a refueling record - only for refuelers"""
    with closing(get_db()) as db:
        db.execute('DELETE FROM refuelings WHERE id = ?', (refueling_id,))
        db.commit()
    flash('תדלוק נמחק בהצלחה', 'success')
    return redirect(url_for('index'))

@app.route('/admin')
@admin_required
def admin():
    """Admin management page"""
    with closing(get_db()) as db:
        drivers = db.execute('SELECT * FROM drivers ORDER BY created_at DESC').fetchall()
        all_trips = db.execute('SELECT * FROM trips ORDER BY date DESC').fetchall()
        all_refuelings = db.execute('SELECT * FROM refuelings ORDER BY date DESC').fetchall()
        
        # Statistics
        total_drivers = len(drivers)
        total_trips = len(all_trips)
        total_refuelings = len(all_refuelings)
        total_km = sum(trip['km'] for trip in all_trips)
        total_cost = sum(ref['cost'] for ref in all_refuelings)
    
    return render_template('admin.html',
                         drivers=drivers,
                         trips=all_trips,
                         refuelings=all_refuelings,
                         total_drivers=total_drivers,
                         total_trips=total_trips,
                         total_refuelings=total_refuelings,
                         total_km=total_km,
                         total_cost=total_cost)

@app.route('/admin/delete_driver/<username>', methods=['POST'])
@admin_required
def delete_driver(username):
    """Delete a driver and all their data"""
    with closing(get_db()) as db:
        db.execute('DELETE FROM trips WHERE username = ?', (username,))
        db.execute('DELETE FROM drivers WHERE username = ?', (username,))
        db.commit()
    flash(f'נהג {username} וכל הנתונים שלו נמחקו', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/toggle_refueler/<username>', methods=['POST'])
@admin_required
def toggle_refueler(username):
    """Toggle refueler status"""
    with closing(get_db()) as db:
        driver = db.execute('SELECT is_refueler FROM drivers WHERE username = ?', (username,)).fetchone()
        if driver:
            new_status = 0 if driver['is_refueler'] else 1
            db.execute('UPDATE drivers SET is_refueler = ? WHERE username = ?', (new_status, username))
            db.commit()
            status_text = 'מתדלק' if new_status else 'לא מתדלק'
            flash(f'{username} עודכן ל-{status_text}', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/toggle_admin/<username>', methods=['POST'])
@admin_required
def toggle_admin(username):
    """Toggle admin status"""
    if username == session['username']:
        flash('לא ניתן להסיר את עצמך ממנהלים', 'error')
        return redirect(url_for('admin'))
    
    with closing(get_db()) as db:
        driver = db.execute('SELECT is_admin FROM drivers WHERE username = ?', (username,)).fetchone()
        if driver:
            new_status = 0 if driver['is_admin'] else 1
            db.execute('UPDATE drivers SET is_admin = ? WHERE username = ?', (new_status, username))
            db.commit()
            status_text = 'מנהל' if new_status else 'לא מנהל'
            flash(f'{username} עודכן ל-{status_text}', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete_trip/<int:trip_id>', methods=['POST'])
@admin_required
def admin_delete_trip(trip_id):
    """Admin delete any trip"""
    with closing(get_db()) as db:
        db.execute('DELETE FROM trips WHERE id = ?', (trip_id,))
        db.commit()
    flash('נסיעה נמחקה', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete_refueling/<int:refueling_id>', methods=['POST'])
@admin_required
def admin_delete_refueling(refueling_id):
    """Admin delete any refueling"""
    with closing(get_db()) as db:
        db.execute('DELETE FROM refuelings WHERE id = ?', (refueling_id,))
        db.commit()
    flash('תדלוק נמחק', 'success')
    return redirect(url_for('admin'))

# Initialize database on startup
try:
    init_db()
    
    # Create default admin if no admins exist
    with closing(get_db()) as db:
        admin_exists = db.execute('SELECT COUNT(*) as count FROM drivers WHERE is_admin = 1').fetchone()
        if admin_exists['count'] == 0:
            default_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
            try:
                db.execute(
                    'INSERT INTO drivers (username, password_hash, is_admin, is_refueler, created_at) VALUES (?, ?, ?, ?, ?)',
                    ('admin', hash_password(default_password), 1, 1, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                )
                db.commit()
                print(f"✅ מנהל ראשון נוצר: username='admin', password='{default_password}'")
            except sqlite3.IntegrityError:
                pass  # Admin already exists
except Exception as e:
    print(f"⚠️ שגיאה באתחול database: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', debug=False, port=port)

