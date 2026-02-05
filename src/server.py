"""
CHRONOS Web Server
Flask backend providing real-time APIs for the Neural Asset Scanner interface.
"""

import os
import sys
import json
import queue
import threading
import time
import sqlite3
from datetime import datetime
from flask import Flask, jsonify, Response, send_from_directory, request
from flask_cors import CORS

# Add src directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from manager import DatabaseManager

# Configuration
DB_FILE = os.path.join(os.path.dirname(__file__), "..", "github.db")
WEB_DIR = os.path.join(os.path.dirname(__file__), "..", "web")

app = Flask(__name__, static_folder=WEB_DIR)
CORS(app)

# Global state for scanner
scanner_thread = None
scanner_running = False
log_queue = queue.Queue()


# =====================
# STATIC FILE SERVING
# =====================

@app.route("/")
def serve_index():
    """Serve the main HTML file."""
    return send_from_directory(WEB_DIR, "index.html")


@app.route("/<path:filename>")
def serve_static(filename):
    """Serve static files (CSS, JS, etc.)."""
    return send_from_directory(WEB_DIR, filename)


# =====================
# API ENDPOINTS
# =====================

@app.route("/api/stats")
def get_stats():
    """
    Get real-time dashboard statistics from the database.
    Returns total keys, tier distribution, and risk distribution.
    """
    try:
        con = sqlite3.connect(DB_FILE)
        cur = con.cursor()
        
        # Total keys
        cur.execute("SELECT COUNT(*) FROM APIKeys")
        total = cur.fetchone()[0]
        
        # Tier distribution
        cur.execute("SELECT model_tier, COUNT(*) FROM APIKeys GROUP BY model_tier")
        tiers = {row[0] or "Unknown": row[1] for row in cur.fetchall()}
        
        # Risk distribution
        cur.execute("SELECT risk_score, COUNT(*) FROM APIKeys GROUP BY risk_score")
        risks = {str(row[0] or 0): row[1] for row in cur.fetchall()}
        
        # Active vs inactive
        cur.execute("SELECT COUNT(*) FROM APIKeys WHERE status = 'yes'")
        active = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM APIKeys WHERE status != 'yes'")
        inactive = cur.fetchone()[0]
        
        con.close()
        
        return jsonify({
            "total": total,
            "active": active,
            "inactive": inactive,
            "tiers": tiers,
            "risks": risks
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/keys")
def get_keys():
    """
    Get all API keys for the vault display.
    Keys are masked for security.
    """
    try:
        con = sqlite3.connect(DB_FILE)
        cur = con.cursor()
        
        cur.execute("""
            SELECT 
                apiKey, 
                status, 
                model_tier, 
                risk_score, 
                context_tag, 
                first_found_at,
                lastChecked
            FROM APIKeys 
            ORDER BY first_found_at DESC
        """)
        
        rows = cur.fetchall()
        con.close()
        
        keys = []
        for row in rows:
            api_key = row[0]
            # Mask the key for display (show first 10 and last 6 chars)
            if len(api_key) > 20:
                masked = f"{api_key[:10]}...{api_key[-6:]}"
            else:
                masked = api_key
            
            keys.append({
                "key": masked,
                "full_key": api_key,  # Include full key for copy functionality
                "status": row[1] or "unknown",
                "tier": row[2] or "Unknown",
                "risk": row[3] or 0,
                "context": row[4] or "Unclassified",
                "found_at": row[5] or row[6] or datetime.now().isoformat()
            })
        
        return jsonify(keys)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    """
    Start the GitHub scanner in a background thread.
    """
    global scanner_thread, scanner_running
    
    if scanner_running:
        return jsonify({"status": "already_running"})
    
    scanner_running = True
    
    def run_scanner():
        global scanner_running
        try:
            # Log start
            log_queue.put("⚡ INITIALIZING NEURAL MEMORY CORE...")
            log_queue.put("🚀 LAUNCHING CHROMIUM INTERCEPTOR...")
            
            # Import and run the scanner
            from main import APIKeyLeakageScanner
            from configs import KEYWORDS, LANGUAGES
            
            log_queue.put("📡 CONNECTING TO GITHUB NETWORK...")
            
            scanner = APIKeyLeakageScanner(DB_FILE, KEYWORDS, LANGUAGES)
            
            # Check for existing cookies
            cookie_file = os.path.join(os.path.dirname(__file__), "..", "cookies.pkl")
            if os.path.exists(cookie_file):
                log_queue.put("🔓 AUTHENTICATION TOKENS DETECTED. BYPASSING LOGIN WALL...")
                scanner.login_to_github()
                
                log_queue.put("📡 SCANNING GLOBAL NETWORKS...")
                
                # Override rich.print to capture logs
                import rich
                original_print = rich.print
                
                def capture_print(*args, **kwargs):
                    msg = " ".join(str(a) for a in args)
                    # Strip rich markup
                    import re
                    clean_msg = re.sub(r'\[.*?\]', '', msg)
                    log_queue.put(clean_msg)
                    original_print(*args, **kwargs)
                
                rich.print = capture_print
                
                try:
                    scanner.search()
                    scanner.update_existed_keys()
                    scanner.deduplication()
                finally:
                    rich.print = original_print
                    
                log_queue.put("✅ SCAN COMPLETE. DATABASE SYNCHRONIZED.")
            else:
                log_queue.put("⚠️ NO AUTH TOKENS FOUND. Please run CLI scanner first to authenticate.")
                log_queue.put("Run: cd src && python main.py")
            
        except Exception as e:
            log_queue.put(f"❌ ERROR: {str(e)}")
        finally:
            scanner_running = False
            log_queue.put("SCAN_FINISHED")
    
    scanner_thread = threading.Thread(target=run_scanner, daemon=True)
    scanner_thread.start()
    
    return jsonify({"status": "success"})


@app.route("/api/scan/stop", methods=["POST"])
def stop_scan():
    """
    Stop the running scanner (best effort - signals to stop).
    """
    global scanner_running
    
    if not scanner_running:
        return jsonify({"status": "not_running"})
    
    scanner_running = False
    log_queue.put("🛑 ABORT SIGNAL RECEIVED. TERMINATING SCAN...")
    log_queue.put("SCAN_FINISHED")
    
    return jsonify({"status": "stopped"})


@app.route("/api/stream")
def stream_logs():
    """
    Server-Sent Events endpoint for real-time log streaming.
    """
    def generate():
        while True:
            try:
                # Wait for new log messages with timeout
                msg = log_queue.get(timeout=30)
                yield f"data: {msg}\n\n"
                
                if msg == "SCAN_FINISHED":
                    break
                    
            except queue.Empty:
                # Send heartbeat to keep connection alive
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


@app.route("/api/status")
def get_status():
    """
    Get current scanner status.
    """
    return jsonify({
        "scanning": scanner_running,
        "database_exists": os.path.exists(DB_FILE),
        "cookies_exist": os.path.exists(os.path.join(os.path.dirname(__file__), "..", "cookies.pkl"))
    })


# =====================
# MAIN ENTRY POINT
# =====================

if __name__ == "__main__":
    print("\n" + "="*60)
    print("   CHRONOS // NEURAL ASSET SCANNER // WEB INTERFACE")
    print("="*60)
    print(f"\n📁 Database: {DB_FILE}")
    print(f"🌐 Web Directory: {WEB_DIR}")
    print(f"\n🚀 Server starting at: http://localhost:5050")
    print("="*60 + "\n")
    
    # Use threaded mode for SSE support
    # Port 5050 avoids macOS AirPlay Receiver conflict on port 5000
    app.run(host="0.0.0.0", port=5050, debug=False, threaded=True)

