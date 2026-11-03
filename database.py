import sqlite3
import os

from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'freela.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    # Wait for a concurrent writer instead of failing immediately with "database is locked".
    conn.execute('PRAGMA busy_timeout = 5000')
    return conn


def hash_password(password):
    # PBKDF2 rather than werkzeug's scrypt default: macOS system Python lacks hashlib.scrypt.
    return generate_password_hash(password, method='pbkdf2:sha256')

def _initialize_schema(conn):
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL
    )''')

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('client', 'freelancer')),
            full_name TEXT NOT NULL,
            avatar_initials TEXT,
            
            -- Legacy demo totals, retained for migration compatibility only.
            -- Read users_with_reputation for current values derived from history.
            rating_score REAL DEFAULT 4.9,        -- e.g. 4.9 (out of 5.0)
            completed_jobs INTEGER DEFAULT 35,    -- e.g. 35 completed jobs
            on_time_rate INTEGER DEFAULT 98,      -- e.g. 98%
            dispute_count INTEGER DEFAULT 0,      -- e.g. 0 disputes
            
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Categories table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            icon TEXT NOT NULL
        )
    ''')

    # Jobs / Gigs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            budget REAL NOT NULL,
            delivery_days INTEGER DEFAULT 7,
            
            -- ZK Eligibility Criteria (Public inputs for the circuit)
            min_rating REAL DEFAULT 4.5,            -- minimum rating required (scaled in circuit)
            min_completed_jobs INTEGER DEFAULT 10,  -- minimum jobs completed
            min_on_time_rate INTEGER DEFAULT 90,    -- minimum % on-time
            max_disputes INTEGER DEFAULT 1,         -- maximum allowable disputes
            
            status TEXT DEFAULT 'open' CHECK(status IN ('open', 'in_progress', 'completed')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES users(id)
        )
    ''')

    # Applications table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER NOT NULL,
            freelancer_id INTEGER NOT NULL,
            cover_note TEXT,
            bid_amount REAL,
            
            -- ZK Proof Verification info
            proof_verified INTEGER DEFAULT 0,       -- 1 if valid ZK proof submitted
            zk_proof_hex TEXT,                      -- Proof bytes / string
            zk_public_inputs TEXT,                  -- JSON string of public inputs
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (job_id) REFERENCES jobs(id),
            FOREIGN KEY (freelancer_id) REFERENCES users(id)
        )
    ''')

    # Seed categories
    categories = [
        ('Web Development', 'code'),
        ('Design & Graphics', 'palette'),
        ('Writing & Content', 'file-text'),
        ('Data & Analytics', 'bar-chart'),
        ('Business', 'briefcase'),
        ('Others', 'more-horizontal')
    ]
    cursor.executemany('''
        INSERT OR IGNORE INTO categories (name, icon) VALUES (?, ?)
    ''', categories)

    # Seed users if empty
    cursor.execute('SELECT COUNT(*) as count FROM users')
    if cursor.fetchone()['count'] == 0:
        # Demo accounts all use the password 'password123' (salted werkzeug hash).
        pwd_hash = hash_password('password123')
        
        users_seed = [
            # Clients
            ('client_alice', 'alice@freela.io', pwd_hash, 'client', 'Alice Morgan', 'AM', 0, 0, 0, 0),
            ('client_techcorp', 'tech@corp.io', pwd_hash, 'client', 'Nexus Global Tech', 'NT', 0, 0, 0, 0),
            
            # Freelancers with private stats
            ('alex_dev', 'alex@freela.io', pwd_hash, 'freelancer', 'Alex Rivera', 'AR', 4.9, 120, 99, 0),
            ('sara_design', 'sara@freela.io', pwd_hash, 'freelancer', 'Sara Chen', 'SC', 4.8, 95, 96, 1),
            ('john_writer', 'john@freela.io', pwd_hash, 'freelancer', 'John Miller', 'JM', 4.9, 210, 97, 0),
            ('data_guru', 'guru@freela.io', pwd_hash, 'freelancer', 'Devin Vance', 'DV', 4.8, 75, 94, 1),
            ('elena_ui', 'elena@freela.io', pwd_hash, 'freelancer', 'Elena Rostova', 'ER', 4.95, 88, 100, 0)
        ]
        
        cursor.executemany('''
            INSERT INTO users (username, email, password_hash, role, full_name, avatar_initials, rating_score, completed_jobs, on_time_rate, dispute_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', users_seed)

    # Seed initial jobs if empty
    cursor.execute('SELECT COUNT(*) as count FROM jobs')
    if cursor.fetchone()['count'] == 0:
        jobs_seed = [
            (
                1, # client Alice
                'Build a modern responsive website',
                'Web Development',
                'Looking for an expert full-stack developer to build a modern, high-converting landing page and dashboard using HTML5/CSS and modern APIs. Must deliver clean code and responsive layouts.',
                850.0,
                5,
                4.8, # min rating
                25,  # min completed jobs
                95,  # min 95% on-time
                1    # max 1 dispute
            ),
            (
                1,
                'Create a clean and modern brand identity',
                'Design & Graphics',
                'We need a complete brand identity package including primary and secondary logo variants, color palette, typography hierarchy, and a 12-page brand guideline manual.',
                650.0,
                7,
                4.7,
                15,
                90,
                2
            ),
            (
                2, # client TechCorp
                'Write SEO-optimized blog posts for AI SaaS',
                'Writing & Content',
                'Seeking an experienced technical content strategist to write 4 comprehensive, research-backed articles on applied cryptography and zero-knowledge privacy.',
                400.0,
                4,
                4.8,
                20,
                92,
                0
            ),
            (
                2,
                'Data analysis and interactive visualization dashboard',
                'Data & Analytics',
                'Transform large-scale user metrics into clean, interactive analytics dashboards. Requires experience in metric modeling, chart representations, and SQLite integration.',
                950.0,
                10,
                4.8,
                30,
                95,
                1
            ),
            (
                1,
                'SaaS Landing page UI/UX wireframes and prototype',
                'Design & Graphics',
                'Design modern dark and light mode UI screens with sleek glassmorphic aesthetics for a privacy-first web3 productivity suite.',
                500.0,
                6,
                4.6,
                10,
                88,
                2
            ),
            (
                2,
                'Python REST API optimization and database indexing',
                'Web Development',
                'Audit, profile, and optimize an existing SQLite / PostgreSQL database and Flask backend API to handle high concurrency with sub-100ms response times.',
                720.0,
                4,
                4.8,
                35,
                96,
                0
            )
        ]
        
        cursor.executemany('''
            INSERT INTO jobs (client_id, title, category, description, budget, delivery_days, min_rating, min_completed_jobs, min_on_time_rate, max_disputes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', jobs_seed)

    _migrate_reputation(conn)
    _migrate_marketplace(conn)
    _migrate_credentials(conn)


def init_db():
    """Initialize and migrate atomically; never erase existing demo work."""
    conn = get_db_connection()
    try:
        # WAL lets page reads continue while another request writes. It is a
        # persistent file setting and cannot be changed inside a transaction.
        conn.execute('PRAGMA journal_mode = WAL')
        conn.execute('BEGIN IMMEDIATE')
        _initialize_schema(conn)
        if conn.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('Existing database has broken references; migration rolled back.')
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _migrate_reputation(conn):
    conn.execute('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)')
    if conn.execute('SELECT 1 FROM schema_migrations WHERE version = 1').fetchone():
        return
    # One row is one completed AND rated historical job. References identify
    # imported/demo history, independently of the current marketplace listings.
    conn.execute('''CREATE TABLE reputation_records (
        id INTEGER PRIMARY KEY,
        job_reference TEXT NOT NULL UNIQUE CHECK(length(trim(job_reference)) > 0),
        freelancer_id INTEGER NOT NULL REFERENCES users(id),
        client_id INTEGER NOT NULL REFERENCES users(id),
        rating_scaled INTEGER NOT NULL
            CHECK(typeof(rating_scaled) = 'integer' AND rating_scaled BETWEEN 100 AND 500),
        on_time INTEGER NOT NULL CHECK(typeof(on_time) = 'integer' AND on_time IN (0, 1)),
        disputed INTEGER NOT NULL CHECK(typeof(disputed) = 'integer' AND disputed IN (0, 1)),
        completed_at TEXT NOT NULL CHECK(length(completed_at) = 10
            AND date(completed_at, '+0 days') IS NOT NULL
            AND date(completed_at, '+0 days') = completed_at),
        is_demo INTEGER NOT NULL DEFAULT 0 CHECK(is_demo IN (0, 1)),
        CHECK(freelancer_id != client_id)
    )''')
    conn.execute('CREATE INDEX reputation_by_freelancer ON reputation_records(freelancer_id, completed_at, id)')
    # Fail rather than silently delete existing duplicates during migration.
    conn.execute('CREATE UNIQUE INDEX one_application_per_job ON applications(job_id, freelancer_id)')
    for operation in ('INSERT', 'UPDATE'):
        conn.execute(f'''CREATE TRIGGER reputation_roles_{operation.lower()}
            BEFORE {operation} ON reputation_records
            BEGIN
                SELECT CASE WHEN COALESCE((SELECT role FROM users WHERE id=NEW.freelancer_id), '') != 'freelancer'
                    THEN RAISE(ABORT, 'Reputation owner must be a freelancer') END;
                SELECT CASE WHEN COALESCE((SELECT role FROM users WHERE id=NEW.client_id), '') != 'client'
                    THEN RAISE(ABORT, 'Reputation reviewer must be a client') END;
            END''')
    conn.execute('''CREATE TRIGGER protect_reputation_roles BEFORE UPDATE OF role ON users
        WHEN NEW.role != OLD.role AND (
            EXISTS(SELECT 1 FROM reputation_records WHERE freelancer_id=OLD.id)
            OR EXISTS(SELECT 1 FROM reputation_records WHERE client_id=OLD.id))
        BEGIN SELECT RAISE(ABORT, 'User role is referenced by reputation history'); END''')
    # Old summary columns remain only for non-destructive migration compatibility.
    # All application/prover reads use this derived view, not those stale columns.
    conn.execute('''CREATE VIEW users_with_reputation AS
        SELECT u.id, u.username, u.email, u.password_hash, u.role, u.full_name,
            u.avatar_initials, u.created_at,
            COALESCE(r.rating_sum, 0) AS rating_sum,
            COALESCE(r.on_time_count, 0) AS on_time_count,
            COALESCE(r.job_count, 0) AS completed_jobs,
            COALESCE(r.disputes, 0) AS dispute_count,
            COALESCE(r.rating_sum / (100.0 * r.job_count), 0) AS rating_score,
            COALESCE(100.0 * r.on_time_count / r.job_count, 0) AS on_time_rate,
            COALESCE(r.rating_sum / r.job_count, 0) AS rating_scaled_floor,
            COALESCE(100 * r.on_time_count / r.job_count, 0) AS on_time_rate_floor
        FROM users u LEFT JOIN (
            SELECT freelancer_id, COUNT(*) AS job_count, SUM(rating_scaled) AS rating_sum,
                SUM(on_time) AS on_time_count, SUM(disputed) AS disputes
            FROM reputation_records GROUP BY freelancer_id
        ) r ON r.freelancer_id = u.id''')
    _seed_demo_history(conn)
    conn.execute('INSERT INTO schema_migrations(version) VALUES (1)')


def _migrate_marketplace(conn):
    """Version 2: hiring lifecycle columns, reviews, and a reputation view without credentials."""
    if conn.execute('SELECT 1 FROM schema_migrations WHERE version = 2').fetchone():
        return
    # The original jobs.status CHECK (open/in_progress/completed) is kept to avoid a
    # table rebuild. "Delivered, awaiting approval" is in_progress with delivered_at set.
    for column in ('hired_freelancer_id INTEGER REFERENCES users(id)',
                   'accepted_at TEXT', 'delivered_at TEXT', 'completed_at TEXT'):
        conn.execute(f'ALTER TABLE jobs ADD COLUMN {column}')
    conn.execute('''ALTER TABLE applications ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'accepted', 'rejected', 'withdrawn'))''')
    conn.execute('CREATE INDEX jobs_by_client ON jobs(client_id, status)')
    # One review per person per job. Client reviews of freelancers also become
    # reputation_records rows; reviews hold the comment and the two-way record.
    conn.execute('''CREATE TABLE reviews (
        id INTEGER PRIMARY KEY,
        job_id INTEGER NOT NULL REFERENCES jobs(id),
        reviewer_id INTEGER NOT NULL REFERENCES users(id),
        reviewee_id INTEGER NOT NULL REFERENCES users(id),
        rating_scaled INTEGER NOT NULL
            CHECK(typeof(rating_scaled) = 'integer' AND rating_scaled BETWEEN 100 AND 500),
        comment TEXT NOT NULL DEFAULT '' CHECK(length(comment) <= 2000),
        disputed INTEGER NOT NULL DEFAULT 0 CHECK(disputed IN (0, 1)),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(job_id, reviewer_id),
        CHECK(reviewer_id != reviewee_id)
    )''')
    # Same derived values as version 1, minus email and password_hash, so no page
    # reading reputation can ever leak credentials. Login reads the users table.
    conn.execute('DROP VIEW users_with_reputation')
    conn.execute('''CREATE VIEW users_with_reputation AS
        SELECT u.id, u.username, u.role, u.full_name, u.avatar_initials, u.created_at,
            COALESCE(r.rating_sum, 0) AS rating_sum,
            COALESCE(r.on_time_count, 0) AS on_time_count,
            COALESCE(r.job_count, 0) AS completed_jobs,
            COALESCE(r.disputes, 0) AS dispute_count,
            COALESCE(r.rating_sum / (100.0 * r.job_count), 0) AS rating_score,
            COALESCE(100.0 * r.on_time_count / r.job_count, 0) AS on_time_rate,
            COALESCE(r.rating_sum / r.job_count, 0) AS rating_scaled_floor,
            COALESCE(100 * r.on_time_count / r.job_count, 0) AS on_time_rate_floor
        FROM users u LEFT JOIN (
            SELECT freelancer_id, COUNT(*) AS job_count, SUM(rating_scaled) AS rating_sum,
                SUM(on_time) AS on_time_count, SUM(disputed) AS disputes
            FROM reputation_records GROUP BY freelancer_id
        ) r ON r.freelancer_id = u.id''')
    conn.execute('INSERT INTO schema_migrations(version) VALUES (2)')


def _migrate_credentials(conn):
    """Version 3: issued history commitments, and what each application's proof was checked against."""
    if conn.execute('SELECT 1 FROM schema_migrations WHERE version = 3').fetchone():
        return
    # One row per issuance. The newest unrevoked version is the freelancer's current
    # credential; a proof must commit to exactly that history. Field elements are
    # stored as 0x-prefixed 64-digit hex. The salt is secret and only feeds the prover.
    conn.execute('''CREATE TABLE credentials (
        id INTEGER PRIMARY KEY,
        freelancer_id INTEGER NOT NULL REFERENCES users(id),
        version INTEGER NOT NULL CHECK(version > 0),
        commitment TEXT NOT NULL CHECK(length(commitment) = 66 AND commitment LIKE '0x%'),
        salt TEXT NOT NULL CHECK(length(salt) = 66 AND salt LIKE '0x%'),
        record_count INTEGER NOT NULL CHECK(record_count > 0),
        issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        revoked_at TIMESTAMP,
        UNIQUE(freelancer_id, version)
    )''')
    conn.execute('''CREATE TRIGGER credential_owner_is_freelancer BEFORE INSERT ON credentials
        BEGIN
            SELECT CASE WHEN COALESCE((SELECT role FROM users WHERE id=NEW.freelancer_id), '') != 'freelancer'
                THEN RAISE(ABORT, 'Credential owner must be a freelancer') END;
        END''')
    conn.execute('ALTER TABLE applications ADD COLUMN credential_id INTEGER REFERENCES credentials(id)')
    conn.execute('ALTER TABLE applications ADD COLUMN vk_hash TEXT')
    conn.execute('INSERT INTO schema_migrations(version) VALUES (3)')


def get_current_credential(conn, freelancer_id):
    return conn.execute('''SELECT * FROM credentials WHERE freelancer_id = ? AND revoked_at IS NULL
        ORDER BY version DESC LIMIT 1''', (freelancer_id,)).fetchone()


def _seed_demo_history(conn):
    """Explicit presentation fixtures, NOT reconstruction of legacy totals."""
    from datetime import date, timedelta
    # username, number of records, rating pattern, late jobs, disputed jobs
    examples = [
        ('alex_dev', 40, [480, 490, 500, 490], 1, 0),
        ('sara_design', 30, [470, 480, 490], 2, 1),
        ('john_writer', 25, [480, 490, 500, 490, 490], 1, 0),
        ('data_guru', 35, [470, 480, 490, 480, 480], 3, 1),
        ('elena_ui', 20, [490, 500], 0, 0),
    ]
    client = conn.execute("SELECT id FROM users WHERE username='client_alice' AND role='client'").fetchone()
    if client is None:
        return
    for username, count, ratings, late, disputes in examples:
        user = conn.execute("SELECT id FROM users WHERE username=? AND role='freelancer'", (username,)).fetchone()
        if user is None:
            continue
        conn.executemany('''INSERT INTO reputation_records
            (job_reference, freelancer_id, client_id, rating_scaled, on_time, disputed, completed_at, is_demo)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)''', [
                (f'DEMO-{username}-{i + 1:03}', user['id'], client['id'], ratings[i % len(ratings)],
                 int(i >= late), int(i < disputes), (date(2026, 1, 1) + timedelta(days=i)).isoformat())
                for i in range(count)
            ])


def get_reputation_records(conn, freelancer_id):
    """Return the complete private history in a deterministic order for the prover."""
    return conn.execute('''SELECT * FROM reputation_records WHERE freelancer_id = ?
        ORDER BY completed_at, id''', (freelancer_id,)).fetchall()

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully at:", DB_PATH)
