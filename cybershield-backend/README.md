# CyberShield Pro Backend

This is the Python Flask backend for CyberShield Pro that provides security event simulation and WebSocket connectivity.

## Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

## Installation

1. Navigate to the backend directory:
   ```bash
   cd cybershield-backend
   ```

2. Install required dependencies:
   ```bash
   pip install flask flask-cors
   ```

   Or create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install flask flask-cors
   ```

## Running the Backend

1. Start the Flask server:
   ```bash
   python server.py
   ```

2. The server will start on `http://localhost:5001`

## API Endpoints

- `GET /api/events` - Retrieve recent security events (HTTP polling)
- `GET /api/health` - Health check endpoint

## Features

- Security event simulation
- HTTP polling for real-time event delivery
- CORS enabled for frontend integration
- Automatic event generation with realistic threat data
- Configurable event generation rates

## Event Types Generated

The backend simulates various security events:

- SQL Injection attempts
- XSS attacks
- Brute force attempts
- Directory traversal attacks
- DDoS attempts
- Malware detection
- Firewall blocks

## Configuration

The server runs on port 5001 by default. You can modify the port and other settings in `server.py`.

## Development

The server runs in debug mode by default for development. For production deployment:

1. Set `debug=False` in the `app.run()` call
2. Configure proper WSGI server (like Gunicorn)
3. Set up proper logging and monitoring

## Integration with Frontend

The frontend connects to this backend via HTTP polling. Make sure both servers are running:

- Frontend: `http://localhost:3000`
- Backend: `http://localhost:5001`

The frontend will automatically switch to demo mode if the backend is unavailable.