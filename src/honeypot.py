"""
CHRONOS ACTIVE DEFENSE
Implements Honeypot routes to trap and ban malicious scanners.
"""

from flask import Blueprint, request, abort, jsonify
from flask_socketio import emit
import time
import rich

honeypot_bp = Blueprint('honeypot', __name__)

# In-memory Blacklist (For production, use Redis)
BLACKLIST = set()
BLACKLISTED_IPS = {}

def is_blacklisted(ip):
    return ip in BLACKLIST

@honeypot_bp.before_app_request
def check_blacklist():
    """Global Middleware to drop blacklisted IPs."""
    ip = request.remote_addr
    if ip in BLACKLIST:
        return abort(403)

def ban_ip(ip, reason="HONEYPOT_TRIGGER"):
    if ip not in BLACKLIST:
        BLACKLIST.add(ip)
        BLACKLISTED_IPS[ip] = {"reason": reason, "timestamp": time.time()}
        rich.print(f"[bold red]🚫 ACTIVE DEFENSE: BANNED IP {ip} ({reason})[/bold red]")
        
        # Broadcast Alert to Dashboard
        try:
            emit('honeypot_triggered', {
                "ip": ip,
                "reason": reason,
                "endpoint": request.path if request else "MANUAL",
                "timestamp": time.time()
            }, namespace='/', broadcast=True)
        except Exception:
            pass # Socket might not be ready or context issue

# --- TRAP ROUTES ---

@honeypot_bp.route('/admin/login')
@honeypot_bp.route('/wp-admin')
@honeypot_bp.route('/config.php')
@honeypot_bp.route('/.env')
@honeypot_bp.route('/id_rsa')
def trap_route():
    """
    Juicy endpoints that should NEVER be accessed by a legitimate user.
    """
    ban_ip(request.remote_addr, reason=f"Accessed Trap: {request.path}")
    return "403 Forbidden", 403

@honeypot_bp.route('/api/admin/keys')
def trap_api():
    ban_ip(request.remote_addr, reason="Accessed Fake Admin API")
    return jsonify({"error": "Unauthorized"}), 401

@honeypot_bp.route('/api/test/honeypot_hit', methods=['POST'])
def test_hit():
    """Manual trigger for demo purposes"""
    ban_ip("192.168.1.666", "MANUAL_TEST_TRIGGER")
    return jsonify({"status": "triggered"}), 200
