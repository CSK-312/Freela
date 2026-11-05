from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, g, abort
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from functools import wraps
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from werkzeug.security import check_password_hash
import database
import integrity
from database import get_db_connection, init_db, hash_password, get_current_credential
from generate_circuit import DEFAULT_HISTORY_CAPACITY

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_secret_key():
    """FREELA_SECRET_KEY if set; otherwise a random key generated once and kept in .local/."""
    configured = os.environ.get('FREELA_SECRET_KEY')
    if configured:
        return configured
    path = os.path.join(BASE_DIR, '.local', 'secret_key')
    try:
        with open(path, encoding='ascii') as f:
            return f.read().strip()
    except FileNotFoundError:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        key = secrets.token_hex(32)
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w', encoding='ascii') as f:
            f.write(key)
        return key


app = Flask(__name__)
app.config.update(
    SECRET_KEY=_load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# Ensure database is present
init_db()


def prepare_demo_credentials():
    """Replace published seed passwords with local presenter-only passwords."""
    seed_names = ('client_alice', 'client_techcorp', 'alex_dev', 'sara_design',
                  'john_writer', 'data_guru', 'elena_ui')
    conn = get_db_connection()
    try:
        rows = conn.execute('SELECT id, username, password_hash FROM users WHERE username IN (' +
                            ','.join('?' for _ in seed_names) + ')', seed_names).fetchall()
        exposed = [row for row in rows if _password_matches(row['password_hash'], 'password123')]
        if not exposed:
            return
        path = os.path.join(os.path.dirname(database.DB_PATH), '.local', 'demo-credentials.txt')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        credentials = [(row, secrets.token_urlsafe(18)) for row in exposed]
        backup_path = None
        try:
            if os.path.exists(path):
                backup_path = path + '.backup-' + secrets.token_hex(4)
                os.replace(path, backup_path)
            with open(path, 'x', encoding='utf-8') as file:
                for row, password in credentials:
                    file.write(f"{row['username']}: {password}\n")
            for row, password in credentials:
                conn.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                             (hash_password(password), row['id']))
            conn.commit()
        except Exception:
            conn.rollback()
            if os.path.exists(path):
                os.unlink(path)
            if backup_path:
                os.replace(backup_path, path)
            raise
    finally:
        conn.close()


USERNAME_RE = re.compile(r'[A-Za-z0-9_]{3,30}')
MIN_PASSWORD_LENGTH = 8
LEGACY_SHA256_RE = re.compile(r'[0-9a-f]{64}')
PUBLIC_ENDPOINTS = {'login', 'register', 'static'}


def _password_matches(stored_hash, password):
    # Accounts created before salted hashing used plain SHA-256; they are upgraded on login.
    if LEGACY_SHA256_RE.fullmatch(stored_hash):
        return hmac.compare_digest(stored_hash, hashlib.sha256(password.encode('utf-8')).hexdigest())
    return check_password_hash(stored_hash, password)


prepare_demo_credentials()


def prepare_admin_account():
    """Create one local presentation admin without a published password."""
    path = os.path.join(os.path.dirname(database.DB_PATH), '.local', 'admin-credentials.txt')
    conn = get_db_connection()
    try:
        if conn.execute('SELECT 1 FROM admins').fetchone():
            return
        if os.path.exists(path):
            raise RuntimeError('Admin credentials exist without an admin account. Check the local database.')
        password = secrets.token_urlsafe(24)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            with open(path, 'x', encoding='utf-8') as file:
                file.write(f'presentation_admin: {password}\n')
            conn.execute('INSERT INTO admins(username, password_hash) VALUES (?, ?)',
                         ('presentation_admin', hash_password(password)))
            conn.commit()
        except Exception:
            conn.rollback()
            if os.path.exists(path):
                os.unlink(path)
            raise
    finally:
        conn.close()


prepare_admin_account()


def csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']


app.jinja_env.globals['csrf_token'] = csrf_token


@app.context_processor
def inject_current_user():
    return {'current_user': g.get('user')}


@app.before_request
def load_user_and_protect():
    g.user = None
    if 'user_id' in session:
        conn = get_db_connection()
        g.user = conn.execute(
            'SELECT id, username, full_name, role, avatar_initials FROM users WHERE id = ?',
            (session['user_id'],)
        ).fetchone()
        conn.close()
        if g.user is None:
            session.clear()
    elif 'admin_id' in session:
        conn = get_db_connection()
        admin = conn.execute('SELECT id, username FROM admins WHERE id = ?',
                             (session['admin_id'],)).fetchone()
        conn.close()
        if admin is None:
            session.clear()
        else:
            g.user = {'id': admin['id'], 'username': admin['username'],
                      'full_name': 'Presentation Admin', 'avatar_initials': 'PA', 'role': 'admin'}

    if request.method == 'POST':
        token = session.get('csrf_token')
        if not token or not hmac.compare_digest(token, request.form.get('csrf_token', '')):
            flash('Your form expired. Please try again.', 'warning')
            return redirect(url_for(request.endpoint if request.endpoint in ('login', 'register') else 'home'))

    if g.user is None and request.endpoint is not None and request.endpoint not in PUBLIC_ENDPOINTS:
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Login required'}), 401
        return redirect(url_for('login'))


@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', code=404, heading='Page not found',
                           message="That page doesn't exist, or you don't have access to it."), 404


@app.errorhandler(500)
def server_error(error):
    return render_template('error.html', code=500, heading='Something went wrong',
                           message='The server hit an unexpected error. Please try again.'), 500


def role_required(role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user['role'] != role:
                if request.path.startswith('/api/'):
                    return jsonify({'error': f'Only {role}s can do that'}), 403
                flash(f'Only {role}s can do that.', 'warning')
                return redirect(url_for('home'))
            return view(*args, **kwargs)
        return wrapped
    return decorator


@contextmanager
def write_transaction():
    """Check-then-update under one write lock; anything not committed is rolled back."""
    conn = get_db_connection()
    try:
        conn.execute('BEGIN IMMEDIATE')
        yield conn
        conn.commit()
    finally:
        conn.close()


# A job delivered but not yet approved is stored as in_progress with delivered_at set.
STAGE_LABELS = {
    'open': 'Open',
    'in_progress': 'In progress',
    'delivered': 'Delivered - awaiting approval',
    'completed': 'Completed',
}


def job_stage(job):
    if job['status'] == 'in_progress' and job['delivered_at']:
        return 'delivered'
    return job['status']


app.jinja_env.globals.update(job_stage=job_stage, STAGE_LABELS=STAGE_LABELS)


def with_client_ratings(conn, jobs):
    """Jobs as dicts with the client's public rating, averaged over signature-checked reviews only."""
    ratings = integrity.client_ratings(conn, [job['client_id'] for job in jobs])
    return [{**dict(job), **ratings[job['client_id']]} for job in jobs]


class FormError(ValueError):
    pass


def form_text(name, label, max_length, required=True):
    value = request.form.get(name, '').strip()
    if required and not value:
        raise FormError(f'{label} is required.')
    if len(value) > max_length:
        raise FormError(f'{label} must be at most {max_length} characters.')
    return value


def form_int(name, label, low, high):
    try:
        value = int(request.form.get(name, ''))
    except ValueError:
        raise FormError(f'{label} must be a whole number.')
    if not low <= value <= high:
        raise FormError(f'{label} must be between {low} and {high}.')
    return value


def form_decimal(name, label, low, high, places=2):
    try:
        value = Decimal(request.form.get(name, '').strip())
    except InvalidOperation:
        raise FormError(f'{label} must be a number.')
    if not value.is_finite() or not Decimal(low) <= value <= Decimal(high):
        raise FormError(f'{label} must be between {low} and {high}.')
    if value != value.quantize(Decimal(1).scaleb(-places)):
        raise FormError(f'{label} can have at most {places} decimal places.')
    return float(value)


@app.route('/')
def home():
    if g.user['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))
    conn = get_db_connection()
    category_filter = request.args.get('category', 'all')
    search_query = request.args.get('q', '').strip()

    query = '''
        SELECT j.*, u.full_name as client_name, u.avatar_initials as client_initials
        FROM jobs j
        JOIN users u ON j.client_id = u.id
        WHERE j.status = 'open'
    '''
    params = []

    if category_filter != 'all':
        query += ' AND j.category = ?'
        params.append(category_filter)

    if search_query:
        query += ' AND (j.title LIKE ? OR j.description LIKE ?)'
        params.append(f'%{search_query}%')
        params.append(f'%{search_query}%')

    query += ' ORDER BY j.id DESC'
    jobs = with_client_ratings(conn, conn.execute(query, params).fetchall())

    # Get categories
    categories = conn.execute('SELECT * FROM categories').fetchall()

    # The logged-in freelancer's own private stats (never anyone else's)
    current_freelancer = None
    if g.user['role'] == 'freelancer':
        current_freelancer = integrity.verified_reputation(conn, g.user['id'])

    conn.close()

    return render_template(
        'index.html',
        jobs=jobs,
        categories=categories,
        current_category=category_filter,
        search_query=search_query,
        current_freelancer=current_freelancer
    )


@app.route('/jobs/<int:job_id>')
def job_detail(job_id):
    conn = get_db_connection()
    job = conn.execute('''
        SELECT j.*, u.full_name AS client_name, u.avatar_initials AS client_initials,
               f.full_name AS freelancer_name,
               datetime(j.accepted_at, '+' || j.delivery_days || ' days') AS due_at
        FROM jobs j
        JOIN users u ON j.client_id = u.id
        LEFT JOIN users f ON j.hired_freelancer_id = f.id
        WHERE j.id = ?
    ''', (job_id,)).fetchone()
    if job is None:
        conn.close()
        abort(404)
    job = with_client_ratings(conn, [job])[0]

    is_owner = job['client_id'] == g.user['id']
    is_hired = job['hired_freelancer_id'] == g.user['id']
    # Only the owner sees who applied; a freelancer only sees their own application.
    applicants = []
    if is_owner:
        applicants = conn.execute('''
            SELECT a.*, u.full_name, u.username, u.avatar_initials, c.version AS credential_version
            FROM applications a JOIN users u ON a.freelancer_id = u.id
            LEFT JOIN credentials c ON a.credential_id = c.id
            WHERE a.job_id = ? ORDER BY a.applied_at
        ''', (job_id,)).fetchall()
    my_application = None
    current_freelancer = None
    if g.user['role'] == 'freelancer':
        my_application = conn.execute(
            'SELECT * FROM applications WHERE job_id = ? AND freelancer_id = ?', (job_id, g.user['id'])
        ).fetchone()
        current_freelancer = integrity.verified_reputation(conn, g.user['id'])
    reviews = {}
    if is_owner or is_hired:
        for review in conn.execute('SELECT * FROM reviews WHERE job_id = ?', (job_id,)):
            reviews['of_freelancer' if review['reviewer_id'] == job['client_id'] else 'of_client'] = {
                **dict(review), 'authentic': integrity.review_is_authentic(review)}
    conn.close()

    return render_template(
        'job_detail.html',
        job=job,
        stage=job_stage(job),
        is_owner=is_owner,
        is_hired=is_hired,
        applicants=applicants,
        my_application=my_application,
        current_freelancer=current_freelancer,
        reviews=reviews
    )


@app.route('/dashboard')
def dashboard():
    if g.user['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))
    conn = get_db_connection()
    if g.user['role'] == 'client':
        jobs = conn.execute('''
            SELECT j.*, f.full_name AS freelancer_name,
                   (SELECT COUNT(*) FROM applications a WHERE a.job_id = j.id) AS applicant_count,
                   (SELECT COUNT(*) FROM applications a WHERE a.job_id = j.id AND a.status = 'pending') AS pending_count
            FROM jobs j LEFT JOIN users f ON j.hired_freelancer_id = f.id
            WHERE j.client_id = ?
            ORDER BY j.id DESC
        ''', (g.user['id'],)).fetchall()
        rating = integrity.client_ratings(conn, [g.user['id']])[g.user['id']]
        my_rating = {'rating': rating['client_rating'], 'count': rating['client_review_count']}
        conn.close()
        return render_template('dashboard_client.html', jobs=jobs, my_rating=my_rating)

    current_freelancer = integrity.verified_reputation(conn, g.user['id'])
    applications = conn.execute('''
        SELECT a.*, j.title, j.budget, j.category
        FROM applications a JOIN jobs j ON a.job_id = j.id
        WHERE a.freelancer_id = ?
        ORDER BY a.applied_at DESC
    ''', (g.user['id'],)).fetchall()
    contracts = conn.execute('''
        SELECT j.*, u.full_name AS client_name,
               datetime(j.accepted_at, '+' || j.delivery_days || ' days') AS due_at,
               mine.rating_scaled AS rating_received, mine.comment AS comment_received, mine.disputed,
               EXISTS(SELECT 1 FROM reviews r WHERE r.job_id = j.id AND r.reviewer_id = ?) AS reviewed_client
        FROM jobs j
        JOIN users u ON j.client_id = u.id
        LEFT JOIN reviews mine ON mine.job_id = j.id AND mine.reviewee_id = j.hired_freelancer_id
        WHERE j.hired_freelancer_id = ?
        ORDER BY j.status = 'completed', j.accepted_at DESC
    ''', (g.user['id'], g.user['id'])).fetchall()
    conn.close()
    return render_template(
        'dashboard_freelancer.html',
        current_freelancer=current_freelancer,
        applications=applications,
        contracts=contracts
    )


def _start_session(user_id):
    session.clear()  # drop any pre-login session data, including the old CSRF token
    session['user_id'] = user_id


@app.route('/admin')
@role_required('admin')
def admin_dashboard():
    conn = get_db_connection()
    try:
        users = conn.execute('SELECT id, username, role FROM users ORDER BY id').fetchall()
        jobs = conn.execute('SELECT id, title, status FROM jobs ORDER BY id DESC').fetchall()
        records = conn.execute('''SELECT r.job_reference, u.username AS freelancer,
            r.rating_scaled, r.on_time, r.disputed FROM reputation_records r
            JOIN users u ON u.id = r.freelancer_id ORDER BY r.id DESC''').fetchall()
        problems = integrity.audit(conn)
    finally:
        conn.close()
    return render_template('admin.html', users=users, jobs=jobs, records=records, problems=problems,
                           key_fingerprint=integrity.public_key_fingerprint())


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db_connection()
        user = conn.execute(
            'SELECT id, password_hash FROM users WHERE username = ? COLLATE NOCASE', (username,)
        ).fetchone()
        if user and _password_matches(user['password_hash'], password):
            if LEGACY_SHA256_RE.fullmatch(user['password_hash']):
                conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hash_password(password), user['id']))
                conn.commit()
            conn.close()
            _start_session(user['id'])
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        admin = conn.execute('SELECT id, password_hash FROM admins WHERE username = ? COLLATE NOCASE',
                             (username,)).fetchone()
        if admin and check_password_hash(admin['password_hash'], password):
            conn.close()
            session.clear()
            session['admin_id'] = admin['id']
            return redirect(url_for('admin_dashboard'))
        conn.close()
        flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role')

        if not USERNAME_RE.fullmatch(username):
            flash('Username must be 3-30 letters, numbers or underscores.', 'danger')
        elif len(password) < MIN_PASSWORD_LENGTH:
            flash(f'Password must be at least {MIN_PASSWORD_LENGTH} characters.', 'danger')
        elif role not in ('client', 'freelancer'):
            flash('Choose whether you are a client or a freelancer.', 'danger')
        else:
            conn = get_db_connection()
            try:
                if (conn.execute('SELECT 1 FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone()
                        or conn.execute('SELECT 1 FROM admins WHERE username = ? COLLATE NOCASE', (username,)).fetchone()):
                    flash('That username is taken.', 'danger')
                else:
                    # users.email is NOT NULL UNIQUE in the original schema; accounts are
                    # username-only, so store a unique placeholder that is never shown or used.
                    # Legacy reputation columns are zeroed; reputation comes from history only.
                    cursor = conn.execute('''
                        INSERT INTO users (username, email, password_hash, role, full_name, avatar_initials,
                                           rating_score, completed_jobs, on_time_rate, dispute_count)
                        VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, 0)
                    ''', (username, f'{username.lower()}@users.freela.local', hash_password(password),
                          role, username, username[:2].upper()))
                    conn.commit()
                    _start_session(cursor.lastrowid)
                    flash(f'Welcome to Freela, {username}!', 'success')
                    return redirect(url_for('home'))
            except sqlite3.IntegrityError:
                flash('That username is taken.', 'danger')
            finally:
                conn.close()
        return render_template('register.html', username=username, role=role)

    return render_template('register.html', username='', role=None)


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/jobs/new', methods=['GET', 'POST'])
@role_required('client')
def create_job():
    conn = get_db_connection()
    categories = conn.execute('SELECT * FROM categories').fetchall()
    conn.close()

    if request.method == 'POST':
        try:
            title = form_text('title', 'Job title', 120)
            category = form_text('category', 'Category', 60)
            if category not in {c['name'] for c in categories}:
                raise FormError('Choose one of the listed categories.')
            description = form_text('description', 'Description', 5000)
            budget = form_decimal('budget', 'Budget', 1, 1_000_000)
            delivery_days = form_int('delivery_days', 'Delivery time', 1, 365)

            # ZK public constraints, limited to what the circuit can check
            min_rating = form_decimal('min_rating', 'Minimum rating', 1, 5)
            min_completed_jobs = form_int('min_completed_jobs', 'Minimum completed jobs', 0, DEFAULT_HISTORY_CAPACITY)
            min_on_time_rate = form_int('min_on_time_rate', 'Minimum on-time rate', 0, 100)
            max_disputes = form_int('max_disputes', 'Maximum disputes', 0, DEFAULT_HISTORY_CAPACITY)
        except FormError as e:
            flash(str(e), 'danger')
            return render_template('create_job.html', categories=categories, form=request.form), 400

        conn = get_db_connection()
        conn.execute('''
            INSERT INTO jobs (client_id, title, category, description, budget, delivery_days, min_rating, min_completed_jobs, min_on_time_rate, max_disputes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (g.user['id'], title, category, description, budget, delivery_days, min_rating, min_completed_jobs, min_on_time_rate, max_disputes))
        conn.commit()
        conn.close()

        flash('Job posted successfully with ZK verification criteria!', 'success')
        return redirect(url_for('home'))

    return render_template('create_job.html', categories=categories, form={})


@app.route('/api/check-eligibility/<int:job_id>', methods=['GET'])
@role_required('freelancer')
def check_eligibility(job_id):
    """
    Simulates / previews circuit condition check locally for the user
    Returns true if private stats satisfy public criteria
    """
    conn = get_db_connection()
    job = conn.execute("SELECT * FROM jobs WHERE id = ? AND status = 'open'", (job_id,)).fetchone()
    freelancer = integrity.verified_reputation(conn, g.user['id'])
    conn.close()

    if not job:
        return jsonify({'error': 'This job is not open for applications'}), 404
    if freelancer['integrity_error']:
        return jsonify({'error': 'Your job history failed its signature check, so no proof can be made: '
                                 + freelancer['integrity_error']}), 409

    # Private inputs vs Public criteria check
    satisfies_rating = freelancer['rating_sum'] >= round(job['min_rating'] * 100) * freelancer['completed_jobs']
    satisfies_jobs = freelancer['completed_jobs'] >= job['min_completed_jobs']
    satisfies_ontime = 100 * freelancer['on_time_count'] >= job['min_on_time_rate'] * freelancer['completed_jobs']
    satisfies_disputes = freelancer['dispute_count'] <= job['max_disputes']

    is_eligible = freelancer['completed_jobs'] > 0 and satisfies_rating and satisfies_jobs and satisfies_ontime and satisfies_disputes

    # Format public criteria (to be used later by Noir & Barretenberg)
    public_inputs = {
        "min_rating": int(round(job['min_rating'] * 100)),  # e.g. 4.8 -> 480
        "min_completed_jobs": job['min_completed_jobs'],
        "min_on_time_rate": job['min_on_time_rate'],
        "max_disputes": job['max_disputes']
    }

    # Display-only summary. The actual witness contains full record arrays.
    private_inputs = {
        "rating": freelancer['rating_scaled_floor'],
        "completed_jobs": freelancer['completed_jobs'],
        "on_time_rate": freelancer['on_time_rate_floor'],
        "disputes": freelancer['dispute_count']
    }

    return jsonify({
        'eligible': is_eligible,
        'criteria': {
            'min_rating': job['min_rating'],
            'min_completed_jobs': job['min_completed_jobs'],
            'min_on_time_rate': job['min_on_time_rate'],
            'max_disputes': job['max_disputes']
        },
        'freelancer_private_stats': {
            'rating': freelancer['rating_score'],
            'completed_jobs': freelancer['completed_jobs'],
            'on_time_rate': freelancer['on_time_rate'],
            'disputes': freelancer['dispute_count']
        },
        'noir_public_inputs': public_inputs,
        'preview_stats': private_inputs
    })


@app.route('/jobs/<int:job_id>/apply', methods=['POST'])
@role_required('freelancer')
def apply_job(job_id):
    try:
        cover_note = form_text('cover_note', 'Cover note', 2000, required=False)
        bid_amount = form_decimal('bid_amount', 'Bid amount', 1, 1_000_000)
    except FormError as e:
        flash(f'{e} Application not submitted.', 'danger')
        return redirect(url_for('job_detail', job_id=job_id))

    # Check everything cheap before starting the (slow) proof.
    conn = get_db_connection()
    job = conn.execute('SELECT status FROM jobs WHERE id = ?', (job_id,)).fetchone()
    existing = conn.execute(
        'SELECT id FROM applications WHERE job_id = ? AND freelancer_id = ?',
        (job_id, g.user['id'])
    ).fetchone()
    conn.close()

    if job is None:
        abort(404)
    if job['status'] != 'open':
        flash('This job is no longer accepting applications.', 'warning')
        return redirect(url_for('job_detail', job_id=job_id))
    if existing:
        flash('You have already applied for this job!', 'info')
        return redirect(url_for('job_detail', job_id=job_id))

    import zk_engine

    # Generate the cryptographic UltraHonk proof with Noir + Barretenberg
    try:
        conn = get_db_connection()
        has_credential = get_current_credential(conn, g.user['id']) is not None
        conn.close()
        if not has_credential:
            # First application: issue the initial credential over the existing history.
            zk_engine.issue_credential(g.user['id'])
        zk_res = zk_engine.generate_and_verify_zk_proof(freelancer_id=g.user['id'], job_id=job_id)
        if zk_res.get('success') is not True:
            flash(f"Proof failed: {zk_res.get('error') or 'The proof process did not complete.'} Application not submitted.", 'danger')
            return redirect(url_for('job_detail', job_id=job_id))

        if zk_res.get('verified') is not True:
            flash('Proof verification failed. Application not submitted.', 'danger')
            return redirect(url_for('job_detail', job_id=job_id))

        real_proof_hex = zk_res.get('proof_hex', '')
        if not real_proof_hex:
            flash('Verified proof data is missing. Application not submitted.', 'danger')
            return redirect(url_for('job_detail', job_id=job_id))
        public_inputs_json = json.dumps(zk_res['prover_data']['public_inputs'])
    except Exception as e:
        flash(f"ZK Engine Error: {str(e)} Application not submitted.", 'danger')
        return redirect(url_for('job_detail', job_id=job_id))

    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO applications (job_id, freelancer_id, cover_note, bid_amount, proof_verified, zk_proof_hex,
                                      zk_public_inputs, credential_id, vk_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (job_id, g.user['id'], cover_note, bid_amount, 1, real_proof_hex, public_inputs_json,
              zk_res.get('credential_id'), zk_res.get('vk_hash')))
        conn.commit()
    except sqlite3.IntegrityError:
        # A second submission finished first; the unique index keeps only one.
        flash('You have already applied for this job!', 'info')
        return redirect(url_for('job_detail', job_id=job_id))
    finally:
        conn.close()

    flash('Success! UltraHonk ZK Proof generated via Noir & verified via Barretenberg (Proof length: ' + str(len(real_proof_hex)) + ' hex chars).', 'success')
    return redirect(url_for('job_detail', job_id=job_id))


def _owned_application(conn, application_id, owner_column):
    row = conn.execute('''
        SELECT a.*, j.client_id, j.status AS job_status
        FROM applications a JOIN jobs j ON a.job_id = j.id
        WHERE a.id = ?
    ''', (application_id,)).fetchone()
    if row is None or row[owner_column] != g.user['id']:
        abort(404)
    return row


@app.route('/applications/<int:application_id>/accept', methods=['POST'])
@role_required('client')
def accept_application(application_id):
    with write_transaction() as conn:
        application = _owned_application(conn, application_id, 'client_id')
        job_id = application['job_id']
        if application['job_status'] != 'open' or application['status'] != 'pending':
            flash('That application can no longer be accepted.', 'warning')
            return redirect(url_for('job_detail', job_id=job_id))
        if application['proof_verified'] != 1:
            flash('Only applicants with a verified ZK proof can be hired.', 'danger')
            return redirect(url_for('job_detail', job_id=job_id))
        conn.execute('''UPDATE jobs SET status = 'in_progress', hired_freelancer_id = ?, accepted_at = CURRENT_TIMESTAMP
            WHERE id = ?''', (application['freelancer_id'], job_id))
        conn.execute("UPDATE applications SET status = 'accepted' WHERE id = ?", (application_id,))
        conn.execute("UPDATE applications SET status = 'rejected' WHERE job_id = ? AND status = 'pending'", (job_id,))
    flash('Freelancer hired. The other applicants were declined.', 'success')
    return redirect(url_for('job_detail', job_id=job_id))


@app.route('/applications/<int:application_id>/reject', methods=['POST'])
@role_required('client')
def reject_application(application_id):
    with write_transaction() as conn:
        application = _owned_application(conn, application_id, 'client_id')
        if application['job_status'] == 'open' and application['status'] == 'pending':
            conn.execute("UPDATE applications SET status = 'rejected' WHERE id = ?", (application_id,))
            flash('Application declined.', 'info')
    return redirect(url_for('job_detail', job_id=application['job_id']))


@app.route('/applications/<int:application_id>/withdraw', methods=['POST'])
@role_required('freelancer')
def withdraw_application(application_id):
    with write_transaction() as conn:
        application = _owned_application(conn, application_id, 'freelancer_id')
        if application['status'] == 'pending':
            conn.execute("UPDATE applications SET status = 'withdrawn' WHERE id = ?", (application_id,))
            flash('Application withdrawn.', 'info')
    return redirect(url_for('job_detail', job_id=application['job_id']))


def _job_for(conn, job_id, owner_column):
    job = conn.execute('SELECT * FROM jobs WHERE id = ?', (job_id,)).fetchone()
    if job is None or job[owner_column] != g.user['id']:
        abort(404)
    return job


@app.route('/jobs/<int:job_id>/deliver', methods=['POST'])
@role_required('freelancer')
def deliver_job(job_id):
    with write_transaction() as conn:
        job = _job_for(conn, job_id, 'hired_freelancer_id')
        if job_stage(job) != 'in_progress':
            flash('This job is not waiting for delivery.', 'warning')
            return redirect(url_for('job_detail', job_id=job_id))
        conn.execute('UPDATE jobs SET delivered_at = CURRENT_TIMESTAMP WHERE id = ?', (job_id,))
    flash('Marked as delivered. The client can now approve and review your work.', 'success')
    return redirect(url_for('job_detail', job_id=job_id))


@app.route('/jobs/<int:job_id>/complete', methods=['POST'])
@role_required('client')
def complete_job(job_id):
    try:
        rating_scaled = form_int('rating', 'Rating', 1, 5) * 100
        comment = form_text('comment', 'Comment', 2000, required=False)
    except FormError as e:
        flash(str(e), 'danger')
        return redirect(url_for('job_detail', job_id=job_id))
    disputed = 1 if request.form.get('disputed') else 0

    with write_transaction() as conn:
        job = _job_for(conn, job_id, 'client_id')
        if job_stage(job) != 'delivered':
            flash('Only delivered work can be approved.', 'warning')
            return redirect(url_for('job_detail', job_id=job_id))
        conn.execute("UPDATE jobs SET status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?", (job_id,))
        integrity.add_review(conn, job_id, g.user['id'], job['hired_freelancer_id'], rating_scaled, comment, disputed)
        # Feedback loop: the completed, rated job joins the freelancer's private history,
        # so their next proof is computed over it. On time = delivered within delivery_days
        # of being hired, measured by the server rather than reported by either side.
        on_time, today = conn.execute('''SELECT julianday(delivered_at) <= julianday(accepted_at) + delivery_days,
            date('now') FROM jobs WHERE id = ?''', (job_id,)).fetchone()
        integrity.append_reputation_record(conn, f'JOB-{job_id}', job['hired_freelancer_id'], g.user['id'],
                                           rating_scaled, on_time, disputed, today)
    # Reissue the freelancer's credential so their next proof commits to the new history.
    import zk_engine
    try:
        zk_engine.issue_credential(job['hired_freelancer_id'])
        flash("Job completed. Your review was added to the freelancer's private history and their credential was reissued.", 'success')
    except Exception as e:
        flash(f"Job completed and your review was saved, but the freelancer's credential could not be reissued yet: {e}", 'warning')
    return redirect(url_for('job_detail', job_id=job_id))


@app.route('/jobs/<int:job_id>/review-client', methods=['POST'])
@role_required('freelancer')
def review_client(job_id):
    try:
        rating_scaled = form_int('rating', 'Rating', 1, 5) * 100
        comment = form_text('comment', 'Comment', 2000, required=False)
    except FormError as e:
        flash(str(e), 'danger')
        return redirect(url_for('job_detail', job_id=job_id))

    with write_transaction() as conn:
        job = _job_for(conn, job_id, 'hired_freelancer_id')
        if job['status'] != 'completed':
            flash('You can review the client once the job is completed.', 'warning')
            return redirect(url_for('job_detail', job_id=job_id))
        if conn.execute('SELECT 1 FROM reviews WHERE job_id = ? AND reviewer_id = ?', (job_id, g.user['id'])).fetchone():
            flash('You already reviewed this client.', 'info')
            return redirect(url_for('job_detail', job_id=job_id))
        integrity.add_review(conn, job_id, g.user['id'], job['client_id'], rating_scaled, comment)
    flash('Thanks! Your review of the client was saved.', 'success')
    return redirect(url_for('job_detail', job_id=job_id))


if __name__ == '__main__':
    # Port 5000 is taken by AirPlay Receiver on macOS, so the default is 5001.
    app.run(host='127.0.0.1', port=int(os.environ.get('FREELA_PORT', 5001)),
            debug=os.environ.get('FREELA_DEBUG') == '1')
