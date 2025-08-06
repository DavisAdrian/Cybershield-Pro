# CyberShield Pro Frontend

This is the React frontend for CyberShield Pro, a modern security monitoring dashboard.

## Prerequisites

- Node.js (v14 or higher)
- npm or yarn

## Installation

1. Navigate to the frontend directory:
   ```bash
   cd cybershield-Frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

## Running the Application

1. Start the development server:
   ```bash
   npm start
   ```

2. Open your browser and navigate to `http://localhost:3000`

## Demo Credentials

- **Admin Account** (with 2FA): 
  - Username: `admin`
  - Password: `CyberShield2025!`

- **Demo Account** (no 2FA):
  - Username: `demo` 
  - Password: `demo123`

## Features

- Real-time security monitoring dashboard
- Two-factor authentication (2FA) for admin accounts
- SQL injection and XSS protection demonstrations
- Interactive threat detection and logging
- Dark/light mode toggle
- Responsive design

## Available Scripts

- `npm start` - Runs the app in development mode
- `npm test` - Launches the test runner
- `npm run build` - Builds the app for production
- `npm run eject` - Ejects from Create React App (one-way operation)

## Environment Variables

Create a `.env` file in this directory for configuration:

```
REACT_APP_WEBSOCKET_URL=ws://localhost:5001
REACT_APP_USE_REAL_WEBSOCKET=false
```

## Technologies Used

- React 18
- Lucide React (icons)
- CSS3 with custom properties
- WebSocket API for real-time updates