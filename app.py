from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import hashlib
import json
import os
from database import get_db_connection, init_db

app = Flask(__name__)
app.secret_key = 'freela_zk_secret_key_demo_dev'

# Ensure database is present
init_db()

def hash_pw(pwd):
    return hashlib.sha256(pwd.encode('utf-8')).hexdigest()

@app.before_request
def make_default_session():
    # If not logged in, set default to freelancer 'alex_dev' for immediate seamless exploration
    if 'user_id' not in session:
        session['user_id'] = 3  # alex_dev
        session['username'] = 'alex_dev'
        session['full_name'] = 'Alex Rivera'
        session['role'] = 'freelancer'
        session['initials'] = 'AR'

@app.route('/')
def home():
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
    jobs = conn.execute(query, params).fetchall()

    # Get categories
    categories = conn.execute('SELECT * FROM categories').fetchall()

    # Current user's private stats (if logged in as freelancer)
    current_freelancer = None
    if session.get('role') == 'freelancer':
        current_freelancer = conn.execute(
            'SELECT * FROM users_with_reputation WHERE id = ?', (session.get('user_id'),)
        ).fetchone()

    # Recent applied jobs for current user
    user_applications = []
    if session.get('user_id'):
        user_applications = conn.execute('''
            SELECT a.*, j.title, j.budget, j.category
            FROM applications a
            JOIN jobs j ON a.job_id = j.id
            WHERE a.freelancer_id = ?
            ORDER BY a.applied_at DESC
        ''', (session.get('user_id'),)).fetchall()

    conn.close()

    return render_template(
        'index.html',
        jobs=jobs,
        categories=categories,
        current_category=category_filter,
        search_query=search_query,
        current_freelancer=current_freelancer,
        user_applications=user_applications
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?',
            (username, username)
        ).fetchone()
        conn.close()

        if user and user['password_hash'] == hash_pw(password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            session['role'] = user['role']
            session['initials'] = user['avatar_initials']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password (try password: "password123")', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/switch-user/<int:user_id>')
def switch_user(user_id):
    """Quick helper for test convenience to switch between Client and Freelancer accounts"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users_with_reputation WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['full_name'] = user['full_name']
        session['role'] = user['role']
        session['initials'] = user['avatar_initials']
    return redirect(request.referrer or url_for('home'))

@app.route('/jobs/new', methods=['GET', 'POST'])
def create_job():
    if session.get('role') != 'client':
        flash('Only clients can post new jobs. Switch to Alice or TechCorp account.', 'warning')
        return redirect(url_for('home'))

    if request.method == 'POST':
        title = request.form.get('title')
        category = request.form.get('category')
        description = request.form.get('description')
        budget = float(request.form.get('budget', 500))
        delivery_days = int(request.form.get('delivery_days', 7))

        # ZK public constraints
        min_rating = float(request.form.get('min_rating', 4.5))
        min_completed_jobs = int(request.form.get('min_completed_jobs', 10))
        min_on_time_rate = int(request.form.get('min_on_time_rate', 90))
        max_disputes = int(request.form.get('max_disputes', 1))

        conn = get_db_connection()
        conn.execute('''
            INSERT INTO jobs (client_id, title, category, description, budget, delivery_days, min_rating, min_completed_jobs, min_on_time_rate, max_disputes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], title, category, description, budget, delivery_days, min_rating, min_completed_jobs, min_on_time_rate, max_disputes))
        conn.commit()
        conn.close()

        flash('Job posted successfully with ZK verification criteria!', 'success')
        return redirect(url_for('home'))

    conn = get_db_connection()
    categories = conn.execute('SELECT * FROM categories').fetchall()
    conn.close()
    return render_template('create_job.html', categories=categories)

@app.route('/api/check-eligibility/<int:job_id>', methods=['GET'])
def check_eligibility(job_id):
    """
    Simulates / previews circuit condition check locally for the user
    Returns true if private stats satisfy public criteria
    """
    if 'user_id' not in session or session.get('role') != 'freelancer':
        return jsonify({'eligible': False, 'error': 'Must be logged in as a freelancer'})

    conn = get_db_connection()
    job = conn.execute('SELECT * FROM jobs WHERE id = ?', (job_id,)).fetchone()
    freelancer = conn.execute('SELECT * FROM users_with_reputation WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    if not job or not freelancer:
        return jsonify({'error': 'Job or User not found'}), 404

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
def apply_job(job_id):
    if session.get('role') != 'freelancer':
        flash('Only freelancers can apply to jobs.', 'warning')
        return redirect(url_for('home'))

    cover_note = request.form.get('cover_note', '')
    bid_amount = float(request.form.get('bid_amount', 0))

    conn = get_db_connection()
    # Check if already applied
    existing = conn.execute(
        'SELECT id FROM applications WHERE job_id = ? AND freelancer_id = ?',
        (job_id, session['user_id'])
    ).fetchone()

    if existing:
        flash('You have already applied for this job!', 'info')
        conn.close()
        return redirect(url_for('home'))

    from zk_engine import generate_and_verify_zk_proof

    # Generate the cryptographic UltraHonk proof with Noir + Barretenberg
    try:
        zk_res = generate_and_verify_zk_proof(freelancer_id=session['user_id'], job_id=job_id)
        if zk_res.get('success') is not True:
            flash(f"Proof failed: {zk_res.get('error') or 'The proof process did not complete.'} Application not submitted.", 'danger')
            conn.close()
            return redirect(url_for('home'))

        if zk_res.get('verified') is not True:
            flash('Proof verification failed. Application not submitted.', 'danger')
            conn.close()
            return redirect(url_for('home'))

        real_proof_hex = zk_res.get('proof_hex', '')
        if not real_proof_hex:
            flash('Verified proof data is missing. Application not submitted.', 'danger')
            conn.close()
            return redirect(url_for('home'))
        public_inputs_json = json.dumps(zk_res['prover_data']['public_inputs'])

        conn.execute('''
            INSERT INTO applications (job_id, freelancer_id, cover_note, bid_amount, proof_verified, zk_proof_hex, zk_public_inputs)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            job_id,
            session['user_id'],
            cover_note,
            bid_amount,
            1,
            real_proof_hex,
            public_inputs_json
        ))
        conn.commit()
        conn.close()

        flash('Success! UltraHonk ZK Proof generated via Noir & verified via Barretenberg (Proof length: ' + str(len(real_proof_hex)) + ' hex chars).', 'success')
    except Exception as e:
        conn.close()
        flash(f"ZK Engine Error: {str(e)}", 'danger')

    return redirect(url_for('home'))

@app.route('/database')
def database_viewer():
    """Simple UI to easily inspect and review the SQLite database directly from the browser"""
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users_with_reputation').fetchall()
    jobs = conn.execute('''
        SELECT j.*, u.full_name as client_name 
        FROM jobs j JOIN users u ON j.client_id = u.id
    ''').fetchall()
    applications = conn.execute('''
        SELECT a.*, j.title, u.username as freelancer_name 
        FROM applications a 
        JOIN jobs j ON a.job_id = j.id
        JOIN users u ON a.freelancer_id = u.id
    ''').fetchall()
    conn.close()

    return render_template(
        'database_viewer.html',
        users=users,
        jobs=jobs,
        applications=applications
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
