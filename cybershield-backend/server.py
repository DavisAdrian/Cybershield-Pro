#!/usr/bin/env python3
"""
CyberShield Pro - Real-Time Security Feed WebSocket Server
A Flask-SocketIO server that provides real-time security events to the frontend.

Installation:
pip install flask flask-socketio flask-cors

Usage:
python server.py

The server will run on http://localhost:5001
WebSocket endpoint: ws://localhost:5001/socket.io/
"""

from flask import Flask, render_template_string, request
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
import time
import random
import threading
import json
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cybershield-demo-secret-key'

CORS(app, origins=["http://localhost:3000", "http://127.0.0.1:3000"])

socketio = SocketIO(app, cors_allowed_origins=["http://localhost:3000", "http://127.0.0.1:3000"])

connected_clients = set()
security_feed_active = False
recent_events = []
MAX_EVENTS_HISTORY = 10

# Sample threat data for realistic simulation
THREAT_TYPES = [
    "SQL Injection",
    "XSS Attack", 
    "Brute Force Attack",
    "Directory Traversal",
    "CSRF Attack",
    "DDoS Attempt",
    "Malware Detection",
    "Unauthorized Access",
    "Data Exfiltration",
    "Privilege Escalation"
]

THREAT_SOURCES = [
    "203.0.113.45", "198.51.100.178", "192.0.2.146", "185.220.101.182",
    "172.16.254.1", "10.0.0.23", "192.168.1.45", "203.113.45.67",
    "198.18.0.25", "172.31.0.100", "10.1.1.50", "192.168.100.200"
]

SYSTEM_MESSAGES = [
    "Firewall rules updated",
    "New malware signature added",
    "Security scan completed", 
    "Backup verification successful",
    "SSL certificate renewed",
    "Intrusion detection calibrated",
    "Threat intelligence updated",
    "Security audit completed",
    "Vulnerability patch applied",
    "Access controls reviewed"
]

def generate_security_event():
    """Generate a realistic security event"""
    event_type = random.choice(['threat_detected', 'stats_update', 'system_alert'])
    
    if event_type == 'threat_detected':
        return {
            'type': 'threat_detected',
            'data': {
                'threatType': random.choice(THREAT_TYPES),
                'source': random.choice(THREAT_SOURCES),
                'severity': random.choice(['LOW', 'MEDIUM', 'HIGH']),
                'status': random.choice(['BLOCKED', 'QUARANTINED', 'MONITORED']),
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'description': f"Detected at {datetime.now().strftime('%H:%M:%S')}"
            }
        }
    
    elif event_type == 'stats_update':
        return {
            'type': 'stats_update', 
            'data': {
                'activeConnections': random.randint(-20, 30),
                'blockedAttacks': random.randint(0, 3),
                'newSecurityEvent': random.random() > 0.7,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        }
    
    else:
        return {
            'type': 'system_alert',
            'data': {
                'message': random.choice(SYSTEM_MESSAGES),
                'level': random.choice(['info', 'warning', 'critical']),
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'source': 'system'
            }
        }

def security_feed_worker():
    """Background worker that sends security events"""
    global security_feed_active, recent_events
    
    while security_feed_active:
        if connected_clients or True:
            # Generate event with varying frequency
            if random.random() > 0.3:
                event = generate_security_event()
                logger.info(f"Broadcasting event: {event['type']} to {len(connected_clients)} Socket.IO clients")
                
                # Store event for HTTP polling
                recent_events.append(event)
                if len(recent_events) > MAX_EVENTS_HISTORY:
                    recent_events.pop(0)
                
                if connected_clients:
                    socketio.emit('message', event, room='security_feed')
        
        time.sleep(random.uniform(1, 3))

@app.route('/')
def index():
    """Basic status page"""
    status_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyberShield Pro - Security Feed Server</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .status { padding: 10px; border-radius: 4px; margin: 10px 0; }
            .running { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
            h1 { color: #333; }
            .endpoint { background: #f8f9fa; padding: 15px; border-left: 4px solid #007bff; margin: 15px 0; }
            code { background: #f8f9fa; padding: 2px 4px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ CyberShield Pro - Security Feed Server</h1>
            <div class="status running">
                ✅ Server Status: Running
            </div>
            <div class="status info">
                📊 Connected Clients: {{ client_count }}
            </div>
            <div class="status info">
                🔄 Security Feed: {{ feed_status }}
            </div>
            
            <h2>WebSocket Endpoints</h2>
            <div class="endpoint">
                <strong>Socket.IO:</strong><br>
                <code>ws://localhost:5001/socket.io/</code><br>
                <small>For Socket.IO connections</small>
            </div>
            <div class="endpoint">
                <strong>HTTP Polling:</strong><br>
                <code>http://localhost:5001/api/events</code><br>
                <small>For HTTP-based real-time events (more reliable)</small>
            </div>
            
            <h2>Frontend Integration</h2>
            <p>To connect your React frontend:</p>
            <ol>
                <li>Set environment variable: <code>REACT_APP_USE_REAL_WEBSOCKET=true</code></li>
                <li>Set WebSocket URL: <code>REACT_APP_WEBSOCKET_URL=ws://localhost:5001</code></li>
                <li>Toggle to "LIVE" mode in the frontend header</li>
                <li>Watch browser console for connection logs</li>
                <li>The system will use HTTP polling for maximum reliability</li>
            </ol>
            
            <h2>Event Types</h2>
            <ul>
                <li><strong>threat_detected:</strong> Real-time security threats</li>
                <li><strong>stats_update:</strong> Connection and attack statistics</li>
                <li><strong>system_alert:</strong> System status messages</li>
            </ul>
            
            <h2>Test Connection</h2>
            <p>You can test the Socket.IO connection by opening browser console and running:</p>
            <code>
                var socket = io('http://localhost:5001');<br>
                socket.on('connect', () => console.log('Connected!'));<br>
                socket.emit('authenticate', {token: 'demo-token'});
            </code>
        </div>
    </body>
    </html>
    """
    return render_template_string(
        status_html, 
        client_count=len(connected_clients),
        feed_status="Active" if security_feed_active else "Inactive"
    )

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    client_id = request.sid
    connected_clients.add(client_id)
    logger.info(f"Client connected: {client_id} (Total: {len(connected_clients)})")
    
    emit('connection_status', {
        'status': 'connected',
        'message': 'Connected to CyberShield Pro Security Feed',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    client_id = request.sid
    connected_clients.discard(client_id)
    logger.info(f"Client disconnected: {client_id} (Total: {len(connected_clients)})")

@socketio.on('authenticate')
def handle_auth(data):
    """Handle client authentication"""
    logger.info(f"Authentication request: {data}")
    
    token = data.get('token', '') if data else ''
    if token in ['demo-token', 'admin-token'] or token.startswith('Bearer '):
        join_room('security_feed')
        emit('auth_success', {
            'status': 'authenticated',
            'message': 'Successfully authenticated for security feed',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        logger.info(f"Client authenticated and joined security_feed room")
    else:
        emit('auth_failed', {
            'error': 'Invalid authentication token',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        logger.info(f"Authentication failed for token: {token}")

@socketio.on('subscribe_security_feed')
def handle_subscribe():
    """Handle subscription to security feed"""
    join_room('security_feed')
    emit('subscription_success', {
        'message': 'Subscribed to security feed',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    })
    logger.info("Client subscribed to security feed")

@socketio.on('unsubscribe_security_feed') 
def handle_unsubscribe():
    """Handle unsubscription from security feed"""
    leave_room('security_feed')
    emit('subscription_ended', {
        'message': 'Unsubscribed from security feed',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    })
    logger.info("Client unsubscribed from security feed")

@socketio.on('ping')
def handle_ping():
    """Handle ping for connection testing"""
    emit('pong', {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'server_time': time.time()
    })

@app.route('/api/events')
def get_events():
    """Get recent security events for HTTP polling"""
    global recent_events
    
    # Return a copy of recent events and clear the list
    events_to_return = recent_events.copy()
    recent_events.clear()
    
    logger.info(f"HTTP polling request - returning {len(events_to_return)} events")
    
    return {
        'events': events_to_return,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'count': len(events_to_return)
    }

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'connected_clients': len(connected_clients),
        'security_feed_active': security_feed_active
    }

@app.route('/api/stats')
def get_stats():
    """Get server statistics"""
    return {
        'connected_clients': len(connected_clients),
        'security_feed_active': security_feed_active,
        'uptime': time.time(),
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }

def start_security_feed():
    """Start the security feed background worker"""
    global security_feed_active
    if not security_feed_active:
        security_feed_active = True
        feed_thread = threading.Thread(target=security_feed_worker, daemon=True)
        feed_thread.start()
        logger.info("🔄 Security feed worker started")

def stop_security_feed():
    """Stop the security feed background worker"""
    global security_feed_active
    security_feed_active = False
    logger.info("⏹️ Security feed worker stopped")

if __name__ == '__main__':
    print("🛡️ Starting CyberShield Pro Security Feed Server...")
    print("📡 Socket.IO endpoint: ws://localhost:5001/socket.io/")
    print("🌐 Web interface: http://localhost:5001")
    print("💡 Set REACT_APP_USE_REAL_WEBSOCKET=true in your frontend")
    print("💡 Set REACT_APP_WEBSOCKET_URL=ws://localhost:5001")
    print("📋 Only requires: pip install flask flask-socketio flask-cors")
    print("=" * 70)
    
    start_security_feed()
    
    try:
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=5001, 
            debug=True,
            use_reloader=False
        )
    except KeyboardInterrupt:
        print("\n🛑 Shutting down server...")
        stop_security_feed()
    except Exception as e:
        print(f"❌ Server error: {e}")
        stop_security_feed()