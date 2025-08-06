import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  Activity,
  AlertTriangle,
  Eye,
  EyeOff,
  CheckCircle,
  Clock,
  Bug,
  Target,
  Lock,
  Key,
  Database,
  AlertCircle,
  UserCheck,
  Zap,
  Smartphone,
  Wifi
} from 'lucide-react';
import './App.css';
 
// Security Configuration - Critical security parameters
const SECURITY_CONFIG = {
  MAX_LOGIN_ATTEMPTS: 3,
  SESSION_TIMEOUT: 30 * 60 * 1000,
  PASSWORD_MIN_LENGTH: 8,
  PASSWORD_REGEX: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
  RATE_LIMIT_WINDOW: 60 * 1000,
  MAX_REQUESTS_PER_WINDOW: 10,
  TOTP_WINDOW: 30000,
  WEBSOCKET_RECONNECT_DELAY: 3000,
  WEBSOCKET_URL: process.env.REACT_APP_WEBSOCKET_URL || 'ws://localhost:5001',
  USE_REAL_WEBSOCKET: process.env.REACT_APP_USE_REAL_WEBSOCKET === 'true'
};

// Security Utilities - Core security functions for input validation and protection
const SecurityUtils = {
  // Input Sanitization - prevents XSS and injection attacks
  sanitizeInput: (input) => {
    if (typeof input !== 'string') return input;
    return input
      .replace(/[<>]/g, '')
      .replace(/['"]/g, '')
      .replace(/[;&|`$]/g, '')
      .trim()
      .substring(0, 255);
  },

  // SQL Injection Prevention - parameterized query simulation
  createSafeQuery: (template, params) => {
    let query = template;
    params.forEach((param, index) => {
      const sanitizedParam = SecurityUtils.sanitizeInput(param);
      query = query.replace(`$${index + 1}`, `'${sanitizedParam}'`);
    });
    return query;
  },

  // Password Validation
  validatePassword: (password) => {
    const errors = [];
    if (password.length < SECURITY_CONFIG.PASSWORD_MIN_LENGTH) {
      errors.push(`Password must be at least ${SECURITY_CONFIG.PASSWORD_MIN_LENGTH} characters`);
    }
    if (!SECURITY_CONFIG.PASSWORD_REGEX.test(password)) {
      errors.push('Password must contain uppercase, lowercase, number, and special character');
    }
    return { isValid: errors.length === 0, errors };
  },

  // Generate secure session token using crypto API
  generateSessionToken: () => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  },

  // CSRF Token generation
  generateCSRFToken: () => {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  },

  // Rate limiting check
  checkRateLimit: (attempts, lastAttempt) => {
    const now = Date.now();
    if (now - lastAttempt < SECURITY_CONFIG.RATE_LIMIT_WINDOW) {
      return attempts >= SECURITY_CONFIG.MAX_REQUESTS_PER_WINDOW;
    }
    return false;
  },

  // Encrypt sensitive data (simulation)
  encryptData: (data) => {
    return btoa(JSON.stringify(data));
  },

  // Decrypt sensitive data (simulation)
  decryptData: (encryptedData) => {
    try {
      return JSON.parse(atob(encryptedData));
    } catch {
      return null;
    }
  },

  // Generate TOTP-style 6-digit code
  generateTOTP: () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
  },

  // Validate TOTP code (simulation - in real app, use proper TOTP library)
  validateTOTP: (userCode, generatedCode, timestamp) => {
    const now = Date.now();
    const isValid = userCode === generatedCode && (now - timestamp) < 60000;
    console.log('TOTP Validation:', { userCode, generatedCode, timestamp, now, timeDiff: now - timestamp, isValid });
    return isValid;
  }
};

// Security Monitoring - Event logging and anomaly detection
const SecurityMonitor = {
  logSecurityEvent: (event) => {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event: event.type,
      details: event.details,
      severity: event.severity,
      source: event.source || 'system'
    };

    console.log('Security Event:', logEntry);
    const logs = JSON.parse(sessionStorage.getItem('securityLogs') || '[]');
    logs.unshift(logEntry);
    sessionStorage.setItem('securityLogs', JSON.stringify(logs.slice(0, 100)));
  },

  detectAnomalousActivity: (userActivity) => {
    const patterns = {
      rapidRequests: userActivity.requestCount > 50,
      suspiciousIPs: userActivity.failedLogins > 5,
      unusualHours: new Date().getHours() < 6 || new Date().getHours() > 22
    };

    return Object.entries(patterns).filter(([_, detected]) => detected).map(([pattern]) => pattern);
  }
};

// Real WebSocket Manager - HTTP polling implementation
const RealWebSocketManager = {
  socket: null,
  callbacks: {},
  reconnectAttempts: 0,
  maxReconnectAttempts: 5,
  isConnected: false,
  pollInterval: null,

  connect: () => {
    try {
      console.log('Connecting to real server via HTTP polling...');
      
      RealWebSocketManager.isConnected = true;
      RealWebSocketManager.reconnectAttempts = 0;
      
      RealWebSocketManager.pollInterval = setInterval(() => {
        if (RealWebSocketManager.isConnected) {
          RealWebSocketManager.pollForEvents();
        }
      }, 2000);
      
      if (RealWebSocketManager.callbacks.onConnect) {
        RealWebSocketManager.callbacks.onConnect();
      }
      
      console.log('Real server connection established via HTTP polling');
      
    } catch (error) {
      console.error('Failed to connect to real server:', error);
      if (RealWebSocketManager.callbacks.onError) {
        RealWebSocketManager.callbacks.onError(error);
      }
    }
  },

  pollForEvents: async () => {
    try {
      const baseUrl = SECURITY_CONFIG.WEBSOCKET_URL.replace('ws://', 'http://').replace('wss://', 'https://');
      const response = await fetch(`${baseUrl}/api/events`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      
      if (response.ok) {
        const data = await response.json();
        const events = data.events || [];
        
        events.forEach(event => {
          if (RealWebSocketManager.callbacks.onMessage) {
            console.log('Received event from server:', event);
            RealWebSocketManager.callbacks.onMessage(event);
          }
        });
        
        if (events.length > 0) {
          RealWebSocketManager.reconnectAttempts = 0;
        }
      }
      
    } catch (error) {
      console.warn('Polling error (will retry):', error.message);
      
      RealWebSocketManager.reconnectAttempts++;
      if (RealWebSocketManager.reconnectAttempts > RealWebSocketManager.maxReconnectAttempts) {
        console.log('Too many polling errors, falling back to demo mode');
        if (RealWebSocketManager.callbacks.onError) {
          RealWebSocketManager.callbacks.onError(new Error('Polling failed'));
        }
      }
    }
  },

  disconnect: () => {
    console.log('Disconnecting from real server...');
    RealWebSocketManager.isConnected = false;
    RealWebSocketManager.reconnectAttempts = RealWebSocketManager.maxReconnectAttempts;
    
    if (RealWebSocketManager.pollInterval) {
      clearInterval(RealWebSocketManager.pollInterval);
      RealWebSocketManager.pollInterval = null;
    }
    
    if (RealWebSocketManager.callbacks.onDisconnect) {
      RealWebSocketManager.callbacks.onDisconnect();
    }
  },

  send: (data) => {
    console.log('HTTP polling mode - data sending not implemented:', data);
  },

  on: (event, callback) => {
    RealWebSocketManager.callbacks[event] = callback;
  }
};
// WebSocket Simulation for Real-Time Security Data (Demo Mode)
const WebSocketSimulator = {
  callbacks: {},
  interval: null,
  isConnected: false,

  connect: () => {
    console.log('Connecting to security monitoring WebSocket simulator...');
    WebSocketSimulator.isConnected = true;
    
    setTimeout(() => {
      if (WebSocketSimulator.callbacks.onConnect) {
        WebSocketSimulator.callbacks.onConnect();
      }
    }, 1000);

    WebSocketSimulator.interval = setInterval(() => {
      if (WebSocketSimulator.isConnected && WebSocketSimulator.callbacks.onMessage) {
        const eventTypes = [
          {
            type: 'threat_detected',
            data: {
              threatType: ['SQL Injection', 'XSS Attack', 'Brute Force', 'Directory Traversal'][Math.floor(Math.random() * 4)],
              source: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
              severity: ['LOW', 'MEDIUM', 'HIGH'][Math.floor(Math.random() * 3)],
              status: 'BLOCKED',
              timestamp: new Date().toISOString()
            }
          },
          {
            type: 'stats_update',
            data: {
              activeConnections: Math.floor(Math.random() * 50) - 25,
              blockedAttacks: Math.random() > 0.7 ? 1 : 0,
              newSecurityEvent: Math.random() > 0.8
            }
          },
          {
            type: 'system_alert',
            data: {
              message: ['High CPU usage detected', 'New malware signature added', 'Firewall rules updated'][Math.floor(Math.random() * 3)],
              level: ['info', 'warning', 'critical'][Math.floor(Math.random() * 3)]
            }
          }
        ];

        if (Math.random() > 0.6) {
          const randomEvent = eventTypes[Math.floor(Math.random() * eventTypes.length)];
          WebSocketSimulator.callbacks.onMessage(randomEvent);
        }
      }
    }, 2000);
  },

  disconnect: () => {
    console.log('Disconnecting from security monitoring WebSocket simulator...');
    WebSocketSimulator.isConnected = false;
    if (WebSocketSimulator.interval) {
      clearInterval(WebSocketSimulator.interval);
    }
    if (WebSocketSimulator.callbacks.onDisconnect) {
      WebSocketSimulator.callbacks.onDisconnect();
    }
  },

  on: (event, callback) => {
    WebSocketSimulator.callbacks[event] = callback;
  }
};

const CyberShieldPro = () => {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [loginAttempts, setLoginAttempts] = useState(0);
  const [lastLoginAttempt, setLastLoginAttempt] = useState(0);
  const [sessionExpiry, setSessionExpiry] = useState(null);

  const [require2FA, setRequire2FA] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [generatedTOTP, setGeneratedTOTP] = useState('');
  const [totpTimestamp, setTotpTimestamp] = useState(0);
  const [pendingCredentials, setPendingCredentials] = useState(null);

  const [websocketConnected, setWebsocketConnected] = useState(false);
  const [realTimeEvents, setRealTimeEvents] = useState([]);

  const [securityLogs, setSecurityLogs] = useState([]);
  const [securityAlerts, setSecurityAlerts] = useState([]);
  const [encryptionStatus] = useState({
    dataAtRest: true,
    dataInTransit: true,
    keyRotation: true
  });

  const [threats, setThreats] = useState([]);
  const [darkMode, setDarkMode] = useState(false);
  const [selectedTab, setSelectedTab] = useState(() => localStorage.getItem('lastTab') || 'overview');
  const [useRealWebSocket, setUseRealWebSocket] = useState(() => {
    // Check localStorage first, then environment variable, then default to false
    const stored = localStorage.getItem('useRealWebSocket');
    if (stored !== null) return stored === 'true';
    return SECURITY_CONFIG.USE_REAL_WEBSOCKET;
  });
  const [realTimeStats, setRealTimeStats] = useState({
    activeConnections: 1247,
    blockedAttacks: 34,
    dataTransfer: '2.4 GB',
    uptime: '99.97%',
    encryptedSessions: 1203,
    sqlInjectionBlocked: 15,
    xssAttemptsBlocked: 8,
    securityScore: 98
  });

  useEffect(() => {
    localStorage.setItem('lastTab', selectedTab);
  }, [selectedTab]);

  useEffect(() => {
    localStorage.setItem('useRealWebSocket', useRealWebSocket.toString());
  }, [useRealWebSocket]);

  const handleLogout = useCallback(() => {
    SecurityMonitor.logSecurityEvent({
      type: 'user_logout',
      severity: 'info',
      details: 'User logged out'
    });

    if (useRealWebSocket) {
      RealWebSocketManager.disconnect();
    } else {
      WebSocketSimulator.disconnect();
    }

    setIsLoggedIn(false);
    setSessionExpiry(null);
    setLoginAttempts(0);
    setRequire2FA(false);
    setTotpCode('');
    setGeneratedTOTP('');
    setPendingCredentials(null);
    setWebsocketConnected(false);
  }, [useRealWebSocket]);

  // Handle WebSocket messages
  const handleWebSocketMessage = useCallback((event) => {
    switch (event.type) {
      case 'threat_detected':
        const newThreat = {
          id: Date.now(),
          type: event.data.threatType,
          severity: event.data.severity,
          source: event.data.source,
          time: 'Just now',
          status: event.data.status,
          timestamp: event.data.timestamp
        };

        setThreats(prev => [newThreat, ...prev.slice(0, 19)]);
        
        setSecurityAlerts(prev => [{
          id: Date.now(),
          type: `${event.data.threatType} detected and blocked`,
          severity: event.data.severity,
          timestamp: event.data.timestamp
        }, ...prev.slice(0, 9)]);

        SecurityMonitor.logSecurityEvent({
          type: 'threat_detected',
          severity: event.data.severity.toLowerCase(),
          details: `${event.data.threatType} from ${event.data.source} - ${event.data.status}`,
          source: 'websocket'
        });
        break;

      case 'stats_update':
        setRealTimeStats(prev => ({
          ...prev,
          activeConnections: Math.max(0, prev.activeConnections + event.data.activeConnections),
          blockedAttacks: prev.blockedAttacks + event.data.blockedAttacks,
          sqlInjectionBlocked: prev.sqlInjectionBlocked + (event.data.newSecurityEvent && Math.random() > 0.8 ? 1 : 0),
          xssAttemptsBlocked: prev.xssAttemptsBlocked + (event.data.newSecurityEvent && Math.random() > 0.9 ? 1 : 0)
        }));
        break;

      case 'system_alert':
        setRealTimeEvents(prev => [{
          id: Date.now(),
          message: event.data.message,
          level: event.data.level,
          timestamp: new Date().toISOString()
        }, ...prev.slice(0, 4)]);
        break;

      default:
        console.log('Unknown WebSocket event type:', event.type);
        break;
    }
  }, []);

  // Initialize security tokens and WebSocket on mount
  useEffect(() => {
    SecurityUtils.generateCSRFToken();

    const logs = JSON.parse(sessionStorage.getItem('securityLogs') || '[]');
    setSecurityLogs(logs.slice(0, 10));

    const WebSocketManager = useRealWebSocket ? RealWebSocketManager : WebSocketSimulator;

    WebSocketManager.on('onConnect', () => {
      setWebsocketConnected(true);
      SecurityMonitor.logSecurityEvent({
        type: 'websocket_connected',
        severity: 'info',
        details: `${useRealWebSocket ? 'Real-time' : 'Demo'} monitoring connected`
      });
    });

    WebSocketManager.on('onDisconnect', () => {
      setWebsocketConnected(false);
      SecurityMonitor.logSecurityEvent({
        type: 'websocket_disconnected',
        severity: 'warning',
        details: `${useRealWebSocket ? 'Real-time' : 'Demo'} monitoring disconnected`
      });
    });

    WebSocketManager.on('onMessage', (event) => {
      handleWebSocketMessage(event);
    });

    if (useRealWebSocket) {
      RealWebSocketManager.on('onError', (error) => {
        console.error('Real WebSocket failed, falling back to demo mode:', error);
        setUseRealWebSocket(false);
        SecurityMonitor.logSecurityEvent({
          type: 'websocket_fallback',
          severity: 'warning',
          details: 'Failed to connect to real WebSocket, using demo mode'
        });
      });
    }

    return () => {
      WebSocketManager.disconnect();
    };
  }, [handleWebSocketMessage, useRealWebSocket]);

  // Session timeout management
  useEffect(() => {
    if (isLoggedIn && sessionExpiry) {
      const timeoutId = setTimeout(() => {
        SecurityMonitor.logSecurityEvent({
          type: 'session_timeout',
          severity: 'info',
          details: 'User session expired'
        });
        handleLogout();
      }, sessionExpiry - Date.now());

      return () => clearTimeout(timeoutId);
    }
  }, [isLoggedIn, sessionExpiry, handleLogout]);

  // Connect to WebSocket when logged in
  useEffect(() => {
    if (isLoggedIn && !websocketConnected) {
      const WebSocketManager = useRealWebSocket ? RealWebSocketManager : WebSocketSimulator;
      WebSocketManager.connect();
    }
  }, [isLoggedIn, websocketConnected, useRealWebSocket]);

  // Real-time security monitoring
  useEffect(() => {
    if (isLoggedIn) {
      const interval = setInterval(() => {
        setRealTimeStats(prev => ({
          ...prev,
          securityScore: Math.min(100, Math.max(85, prev.securityScore + Math.floor(Math.random() * 3 - 1))),
          uptime: '99.97%',
          dataTransfer: `${(2.4 + Math.random() * 0.5).toFixed(1)} GB`
        }));
      }, 10000);

      return () => clearInterval(interval);
    }
  }, [isLoggedIn]);

  const LoginScreen = () => {
    const [credentials, setCredentials] = useState({ username: '', password: '' });
    const [showPassword, setShowPassword] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [passwordStrength, setPasswordStrength] = useState({ score: 0, feedback: [] });
    const [isRateLimited, setIsRateLimited] = useState(false);

    const handleInputChange = useCallback((field, value) => {
      const sanitizedValue = SecurityUtils.sanitizeInput(value);
      setCredentials(prev => ({ ...prev, [field]: sanitizedValue }));
      setError('');

      if (field === 'password') {
        const validation = SecurityUtils.validatePassword(sanitizedValue);
        setPasswordStrength({
          score: sanitizedValue.length >= 8 ? (validation.isValid ? 4 : 2) : 1,
          feedback: validation.errors
        });
      }
    }, []);

    const handleLogin = async () => {
      if (SecurityUtils.checkRateLimit(loginAttempts, lastLoginAttempt)) {
        setIsRateLimited(true);
        setError('Too many login attempts. Please wait before trying again.');
        return;
      }

      if (!credentials.username || !credentials.password) {
        setError('Please enter both username and password');
        return;
      }

      const passwordValidation = SecurityUtils.validatePassword(credentials.password);
      if (credentials.username === 'admin' && !passwordValidation.isValid) {
        setError('Admin password must meet security requirements');
        return;
      }

      setIsLoading(true);
      setLastLoginAttempt(Date.now());

      setTimeout(() => {
        const validCredentials = [
          { username: 'admin', password: 'CyberShield2025!' },
          { username: 'demo', password: 'demo123' }
        ];

        const isValid = validCredentials.some(
          cred => cred.username === credentials.username && cred.password === credentials.password
        );

        if (isValid) {
          const userRequires2FA = credentials.username === 'admin';
          
          if (userRequires2FA && !require2FA) {
            const totp = SecurityUtils.generateTOTP();
            setGeneratedTOTP(totp);
            setTotpTimestamp(Date.now());
            setPendingCredentials(credentials);
            setRequire2FA(true);
            
            SecurityMonitor.logSecurityEvent({
              type: '2fa_requested',
              severity: 'info',
              details: `2FA required for user ${credentials.username}`,
              source: credentials.username
            });

            setError('');
            setIsLoading(false);
            return;
          }

          completeLogin(credentials.username);
        } else {
          const newAttempts = loginAttempts + 1;
          setLoginAttempts(newAttempts);

          SecurityMonitor.logSecurityEvent({
            type: 'failed_login',
            severity: 'warning',
            details: `Failed login attempt for user ${credentials.username}`,
            source: credentials.username
          });

          if (newAttempts >= SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS) {
            setError('Account temporarily locked due to multiple failed attempts');
            SecurityMonitor.logSecurityEvent({
              type: 'account_lockout',
              severity: 'high',
              details: `Account ${credentials.username} locked after ${newAttempts} failed attempts`,
              source: credentials.username
            });
          } else {
            setError(`Invalid credentials. ${SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS - newAttempts} attempts remaining`);
          }
        }
        setIsLoading(false);
      }, 1500);
    };

    const handleKeyPress = (e) => {
      if (e.key === 'Enter' && !isLoading && !isRateLimited && credentials.username && credentials.password) {
        e.preventDefault();
        handleLogin();
      }
    };

    const completeLogin = (username) => {
      const expiry = Date.now() + SECURITY_CONFIG.SESSION_TIMEOUT;

      setSessionExpiry(expiry);
      setIsLoggedIn(true);
      setLoginAttempts(0);
      setRequire2FA(false);
      setTotpCode('');
      setGeneratedTOTP('');
      setPendingCredentials(null);

      SecurityMonitor.logSecurityEvent({
        type: 'successful_login',
        severity: 'info',
        details: `User ${username} logged in successfully`,
        source: username
      });

      const simulatedThreats = [
        {
          id: 1,
          type: 'SQL Injection Attempt',
          severity: 'HIGH',
          source: '185.220.101.182',
          time: '2 min ago',
          status: 'BLOCKED',
          query: "SELECT * FROM users WHERE id = '1' OR '1'='1'",
          prevention: 'Parameterized queries active'
        },
        {
          id: 2,
          type: 'XSS Attack',
          severity: 'MEDIUM',
          source: '192.168.1.45',
          time: '5 min ago',
          status: 'BLOCKED',
          payload: '<script>alert("XSS")</script>',
          prevention: 'Input sanitization active'
        },
        {
          id: 3,
          type: 'CSRF Attempt',
          severity: 'LOW',
          source: '10.0.0.23',
          time: '8 min ago',
          status: 'BLOCKED',
          prevention: 'CSRF tokens validated'
        },
        {
          id: 4,
          type: 'Directory Traversal',
          severity: 'HIGH',
          source: '203.0.113.45',
          time: '12 min ago',
          status: 'QUARANTINED',
          path: '../../../etc/passwd',
          prevention: 'Path validation active'
        }
      ];

      setThreats(simulatedThreats);
    };

    const handle2FAVerification = () => {
      if (!totpCode || totpCode.length !== 6) {
        setError('Please enter a valid 6-digit code');
        return;
      }

      setIsLoading(true);

      setTimeout(() => {
        if (SecurityUtils.validateTOTP(totpCode, generatedTOTP, totpTimestamp)) {
          SecurityMonitor.logSecurityEvent({
            type: '2fa_successful',
            severity: 'info',
            details: `2FA verification successful for user ${pendingCredentials.username}`,
            source: pendingCredentials.username
          });

          completeLogin(pendingCredentials.username);
        } else {
          SecurityMonitor.logSecurityEvent({
            type: '2fa_failed',
            severity: 'warning',
            details: `2FA verification failed for user ${pendingCredentials.username}`,
            source: pendingCredentials.username
          });

          setError('Invalid or expired verification code');
          setLoginAttempts(prev => prev + 1);
        }
        setIsLoading(false);
      }, 1000);
    };

    const handle2FAKeyPress = (e) => {
      if (e.key === 'Enter' && !isLoading && totpCode.length === 6) {
        e.preventDefault();
        handle2FAVerification();
      }
    };

    const getPasswordStrengthColor = () => {
      if (passwordStrength.score < 2) return 'strength-weak';
      if (passwordStrength.score < 4) return 'strength-medium';
      return 'strength-strong';
    };

    if (require2FA) {
      return (
        <div className="login-container">
          <div className="login-form">
            <div className="logo-section">
              <div className="logo-icon">
                <Shield className="shield-icon" />
              </div>
              <h1 className="app-title">Two-Factor Authentication</h1>
              <p className="app-subtitle">Enter the 6-digit verification code</p>
            </div>

            <div className="security-status-card">
              <div className="security-header">
                <span className="status-title">2FA Required</span>
                <div className="status-indicator">
                  <div className="status-dot"></div>
                  <span className="status-text">SECURE</span>
                </div>
              </div>
              <div className="totp-display">
                <div className="totp-info">
                  <Smartphone className="totp-icon" />
                  <div className="totp-details">
                    <p className="totp-label">Your verification code:</p>
                    <p className="totp-code">{generatedTOTP}</p>
                    <p className="totp-note">
                      Enter this code in your authenticator app or use the code above
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div className="form-card">
              <div className="form-content" onKeyPress={handle2FAKeyPress}>
                <div className="input-group">
                  <label className="input-label">Verification Code</label>
                  <input
                    type="text"
                    value={totpCode}
                    onChange={(e) => {
                      const value = e.target.value.replace(/\D/g, '').slice(0, 6);
                      setTotpCode(value);
                      setError('');
                    }}
                    onPaste={(e) => {
                      e.preventDefault();
                      const paste = (e.clipboardData || window.clipboardData).getData('text');
                      const value = paste.replace(/\D/g, '').slice(0, 6);
                      setTotpCode(value);
                      setError('');
                    }}
                    onKeyPress={handle2FAKeyPress}
                    className="form-input totp-input"
                    placeholder="000000"
                    disabled={isLoading}
                    maxLength="6"
                    autoComplete="off"
                    inputMode="numeric"
                    autoFocus
                  />
                </div>

                <div className="totp-progress">
                  {Array.from({ length: 6 }).map((_, index) => (
                    <div
                      key={index}
                      className={`totp-digit ${index < totpCode.length ? 'filled' : ''}`}
                    >
                      {totpCode[index] || ''}
                    </div>
                  ))}
                </div>

                {error && (
                  <div className="error-alert">
                    <div className="error-content">
                      <AlertCircle className="error-icon" />
                      <span className="error-text">{error}</span>
                    </div>
                  </div>
                )}

                <div className="totp-buttons">
                  <button
                    onClick={handle2FAVerification}
                    disabled={isLoading || totpCode.length !== 6}
                    className={`login-button ${isLoading ? 'loading' : ''}`}
                  >
                    {isLoading ? (
                      <div className="loading-content">
                        <div className="spinner"></div>
                        Verifying...
                      </div>
                    ) : (
                      'Verify Code'
                    )}
                  </button>

                  <button
                    onClick={() => {
                      setRequire2FA(false);
                      setTotpCode('');
                      setGeneratedTOTP('');
                      setPendingCredentials(null);
                      setError('');
                    }}
                    className="cancel-button"
                    disabled={isLoading}
                  >
                    Cancel
                  </button>
                </div>

                <div className="totp-help">
                  <p className="totp-help-text">
                    Code expires in 60 seconds. If expired, go back and try logging in again.
                  </p>
                  <p className="totp-help-text">
                    <strong>Tip:</strong> You can copy and paste the code above: {generatedTOTP}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      );
    }

    return (
      <div className="login-container">
        <div className="login-form">
          <div className="logo-section">
            <div className="logo-icon">
              <Shield className="shield-icon" />
            </div>
            <h1 className="app-title">CyberShield Pro</h1>
            <p className="app-subtitle">Advanced Security Protection System</p>
            <div className="security-status">
              <Lock className="security-icon" />
              <span className="security-text">256-bit Encryption Active</span>
            </div>
          </div>

          <div className="security-status-card">
            <div className="security-header">
              <span className="status-title">Security Status</span>
              <div className="status-indicator">
                <div className="status-dot"></div>
                <span className="status-text">SECURE</span>
              </div>
            </div>
            <div className="security-grid">
              <div className="security-item">
                <Key className="security-item-icon" />
                <span className="security-item-text">SSL/TLS: Active</span>
              </div>
              <div className="security-item">
                <Shield className="security-item-icon" />
                <span className="security-item-text">WAF: Enabled</span>
              </div>
              <div className="security-item">
                <Database className="security-item-icon" />
                <span className="security-item-text">SQL Protection: On</span>
              </div>
              <div className="security-item">
                <Zap className="security-item-icon" />
                <span className="security-item-text">DDoS Shield: Ready</span>
              </div>
            </div>
          </div>

          <div className="form-card">
            <div className="form-content" onKeyPress={handleKeyPress}>
              <div className="input-group">
                <label className="input-label">Username</label>
                <input
                  type="text"
                  value={credentials.username}
                  onChange={(e) => handleInputChange('username', e.target.value)}
                  onKeyPress={handleKeyPress}
                  className="form-input"
                  placeholder="Enter username"
                  disabled={isLoading || isRateLimited}
                  maxLength="50"
                />
              </div>

              <div className="input-group">
                <label className="input-label">Password</label>
                <div className="password-container">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={credentials.password}
                    onChange={(e) => handleInputChange('password', e.target.value)}
                    onKeyPress={handleKeyPress}
                    className="form-input password-input"
                    placeholder="Enter password"
                    disabled={isLoading || isRateLimited}
                    maxLength="100"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="password-toggle"
                  >
                    {showPassword ? <EyeOff className="eye-icon" /> : <Eye className="eye-icon" />}
                  </button>
                </div>

                {credentials.password && (
                  <div className="password-strength">
                    <div className="strength-header">
                      <span className="strength-label">Password Strength:</span>
                      <div className="strength-bar">
                        <div
                          className={`strength-fill ${getPasswordStrengthColor()}`}
                          style={{ width: `${(passwordStrength.score / 4) * 100}%` }}
                        ></div>
                      </div>
                    </div>
                    {passwordStrength.feedback.length > 0 && (
                      <div className="strength-feedback">
                        {passwordStrength.feedback[0]}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {error && (
                <div className="error-alert">
                  <div className="error-content">
                    <AlertCircle className="error-icon" />
                    <span className="error-text">{error}</span>
                  </div>
                </div>
              )}

              {isRateLimited && (
                <div className="warning-alert">
                  <div className="warning-content">
                    <Clock className="warning-icon" />
                    <span className="warning-text">Rate limited. Please wait before retrying.</span>
                  </div>
                </div>
              )}

              {loginAttempts > 0 && (
                <div className="attempts-counter">
                  Login attempts: {loginAttempts}/{SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS}
                </div>
              )}

              <button
                onClick={handleLogin}
                disabled={isLoading || isRateLimited}
                className={`login-button ${isLoading ? 'loading' : ''}`}
              >
                {isLoading ? (
                  <div className="loading-content">
                    <div className="spinner"></div>
                    Authenticating...
                  </div>
                ) : (
                  'Secure Login'
                )}
              </button>

              <div className="demo-credentials">
                <p className="demo-title">Demo Credentials:</p>
                <div className="demo-list">
                  <div>admin / CyberShield2025! (requires 2FA)</div>
                  <div>demo / demo123 (no 2FA)</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const Dashboard = ({ selectedTab, setSelectedTab }) => {
    const handleTabSwitch = useCallback((tabName) => {
      console.log('Switching to tab:', tabName); // Debug log
      setSelectedTab(tabName);
    }, [setSelectedTab]);

    useEffect(() => {
      console.log('Current selected tab:', selectedTab);
    }, [selectedTab]);

    const StatCard = ({ icon: Icon, title, value, subtitle, color = 'blue', trend = null }) => {
      return (
        <div className="stat-card">
          <div className="stat-content">
            <div className={`stat-icon ${color}`}>
              <Icon className="icon" />
            </div>
            <div className="stat-info">
              <p className="stat-title">{title}</p>
              <p className="stat-value">{value}</p>
              {subtitle && <p className="stat-subtitle">{subtitle}</p>}
              {trend && (
                <div className={`trend ${trend > 0 ? 'increase' : 'decrease'}`}>
                  {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}% from last hour
                </div>
              )}
            </div>
          </div>
        </div>
      );
    };

    const SecurityAlert = ({ alert }) => {
      return (
        <div className="threat-alert" key={alert.id}>
          <div className="threat-content">
            <div className="threat-info">
              <div className={`threat-status ${alert.severity.toLowerCase()}`}></div>
              <div className="threat-details">
                <p className="threat-type">{alert.type}</p>
                <p className="threat-source">
                  {new Date(alert.timestamp).toLocaleTimeString()}
                </p>
              </div>
            </div>
            <div className="threat-meta">
              <span className={`severity-badge ${alert.severity.toLowerCase()}`}>
                {alert.severity}
              </span>
            </div>
          </div>
        </div>
      );
    };

    return (
      <div className={`dashboard ${darkMode ? 'dark' : ''}`}>
        <header className="dashboard-header">
          <div className="header-content">
            <div className="header-left">
              <Shield className="header-icon" />
              <h1 className="header-title">CyberShield Pro</h1>
            </div>
            <div className="header-right">
              <div className="websocket-mode-toggle">
                <button
                  onClick={() => {
                    const newMode = !useRealWebSocket;
                    setUseRealWebSocket(newMode);
                    
                    if (useRealWebSocket) {
                      RealWebSocketManager.disconnect();
                    } else {
                      WebSocketSimulator.disconnect();
                    }
                    
                    setWebsocketConnected(false);
                    
                    SecurityMonitor.logSecurityEvent({
                      type: 'websocket_mode_changed',
                      severity: 'info',
                      details: `Switched to ${newMode ? 'Live' : 'Demo'} mode`
                    });
                  }}
                  className={`mode-toggle ${useRealWebSocket ? 'live' : 'demo'}`}
                  title={`Currently in ${useRealWebSocket ? 'Live' : 'Demo'} mode. Click to switch.`}
                >
                  {useRealWebSocket ? '🔴 LIVE' : '🟢 DEMO'}
                </button>
              </div>

              <div className="websocket-status">
                <Wifi className="websocket-icon" />
                <span className={`websocket-text ${websocketConnected ? 'connected' : 'disconnected'}`}>
                  {useRealWebSocket ? 'Live' : 'Demo'}: {websocketConnected ? 'Connected' : 'Disconnected'}
                </span>
              </div>

              <div className="session-timer">
                <Clock className="timer-icon" />
                <span className="timer-text">
                  Session: {Math.floor((sessionExpiry - Date.now()) / 60000)}m remaining
                </span>
              </div>

              <div className="status-indicator">
                <div className="status-dot"></div>
                <span className="status-text">
                  Security Score: {realTimeStats.securityScore}%
                </span>
              </div>

              <button
                onClick={() => setDarkMode(!darkMode)}
                className="theme-toggle"
                title={darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              >
                {darkMode ? '☀️' : '🌙'}
              </button>

              <button
                onClick={handleLogout}
                className="logout-button"
              >
                Logout
              </button>
            </div>
          </div>
        </header>

        <div className="nav-tabs">
          <div className="tabs-container">
            <nav className="tabs-nav">
              {['overview', 'security', 'threats', 'network', 'analytics', 'logs'].map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    handleTabSwitch(tab);
                  }}
                  className={`tab-button ${selectedTab === tab ? 'active' : ''}`}
                >
                  {tab.charAt(0).toUpperCase() + tab.slice(1)}
                </button>
              ))}
            </nav>
          </div>
        </div>

        <main className="dashboard-main">
          {selectedTab === 'overview' && (
            <div className="overview-content">
              <div className="stats-grid">
                <StatCard
                  icon={Activity}
                  title="Active Connections"
                  value={realTimeStats.activeConnections.toLocaleString()}
                  subtitle="Currently monitored"
                  color="blue"
                  trend={2}
                />
                <StatCard
                  icon={Shield}
                  title="Blocked Attacks"
                  value={realTimeStats.blockedAttacks}
                  subtitle="Last 24 hours"
                  color="red"
                  trend={-5}
                />
                <StatCard
                  icon={Lock}
                  title="Encrypted Sessions"
                  value={realTimeStats.encryptedSessions}
                  subtitle="SSL/TLS protected"
                  color="green"
                  trend={1}
                />
                <StatCard
                  icon={Target}
                  title="Security Score"
                  value={`${realTimeStats.securityScore}%`}
                  subtitle="Overall protection"
                  color="purple"
                  trend={0}
                />
              </div>

              <div className="content-grid">
                <div className="content-card">
                  <h3 className="card-title">
                    <AlertTriangle className="title-icon red" />
                    Recent Security Alerts
                  </h3>
                  <div className="security-alerts-list">
                    {securityAlerts.length > 0 ? securityAlerts.map((alert) => (
                      <SecurityAlert key={`alert-${alert.id}`} alert={alert} />
                    )) : (
                      <p className="no-alerts-text">No recent alerts</p>
                    )}
                  </div>
                </div>

                <div className="content-card">
                  <h3 className="card-title">
                    <Database className="title-icon blue" />
                    SQL Injection Protection
                  </h3>
                  <div className="protection-metrics">
                    <div className="protection-item">
                      <span className="protection-label">Attempts Blocked</span>
                      <span className="protection-value">{realTimeStats.sqlInjectionBlocked}</span>
                    </div>
                    <div className="protection-item">
                      <span className="protection-label">XSS Attempts Blocked</span>
                      <span className="protection-value">{realTimeStats.xssAttemptsBlocked}</span>
                    </div>
                    <div className="protection-status">
                      <div className="protection-status-content">
                        <CheckCircle className="protection-status-icon" />
                        <span className="protection-status-text">Parameterized queries active</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="content-card">
                  <h3 className="card-title">
                    <Wifi className="title-icon green" />
                    Live Security Feed
                  </h3>
                  <div className="realtime-events">
                    {realTimeEvents.length > 0 ? realTimeEvents.map((event) => (
                      <div key={`event-${event.id}`} className={`realtime-event ${event.level}`}>
                        <div className="event-content">
                          <div className={`event-indicator ${event.level}`}></div>
                          <div className="event-details">
                            <p className="event-message">{event.message}</p>
                            <p className="event-time">
                              {new Date(event.timestamp).toLocaleTimeString()}
                            </p>
                          </div>
                        </div>
                      </div>
                    )) : (
                      <div className="no-events">
                        <p className="no-events-text">
                          {websocketConnected ? 'Monitoring for real-time events...' : 'WebSocket disconnected'}
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {selectedTab === 'security' && (
            <div className="security-content">
              <h2 className="section-title">Security Configuration</h2>

              <div className="stats-grid">
                <StatCard
                  icon={Database}
                  title="SQL Injection Protection"
                  value="ACTIVE"
                  subtitle="Parameterized queries enabled"
                  color="green"
                />
                <StatCard
                  icon={Shield}
                  title="XSS Protection"
                  value="ENABLED"
                  subtitle="Input sanitization active"
                  color="green"
                />
                <StatCard
                  icon={Key}
                  title="CSRF Protection"
                  value="ACTIVE"
                  subtitle="Token validation enabled"
                  color="green"
                />
                <StatCard
                  icon={Lock}
                  title="Session Security"
                  value="SECURE"
                  subtitle="30min timeout, secure tokens"
                  color="green"
                />
                <StatCard
                  icon={UserCheck}
                  title="Rate Limiting"
                  value="ENABLED"
                  subtitle="10 requests/minute limit"
                  color="green"
                />
                <StatCard
                  icon={Smartphone}
                  title="2FA Protection"
                  value="ENABLED"
                  subtitle="TOTP-based authentication"
                  color="green"
                />
                <StatCard
                  icon={Wifi}
                  title="Real-Time Monitoring"
                  value={websocketConnected ? "CONNECTED" : "OFFLINE"}
                  subtitle="WebSocket security feed"
                  color={websocketConnected ? "green" : "red"}
                />
                <StatCard
                  icon={Zap}
                  title="Input Validation"
                  value="ACTIVE"
                  subtitle="All inputs sanitized"
                  color="green"
                />
              </div>

              <div className="content-card">
                <h3 className="card-title">Real-Time Monitoring Status</h3>
                <div className="websocket-details">
                  <div className="websocket-status-item">
                    <span className="websocket-label">Connection Status</span>
                    <div className="websocket-status-value">
                      <div className={`websocket-indicator ${websocketConnected ? 'connected' : 'disconnected'}`}></div>
                      <span className={`websocket-status-text ${websocketConnected ? 'connected' : 'disconnected'}`}>
                        {websocketConnected ? 'Connected' : 'Disconnected'}
                      </span>
                    </div>
                  </div>
                  <div className="websocket-status-item">
                    <span className="websocket-label">Events Received</span>
                    <span className="websocket-value">{realTimeEvents.length}</span>
                  </div>
                  <div className="websocket-status-item">
                    <span className="websocket-label">Threats Detected (Live)</span>
                    <span className="websocket-value">{realTimeEvents.filter(e => e.level === 'critical').length}</span>
                  </div>
                </div>
              </div>

              <div className="content-card">
                <h3 className="card-title">Encryption Status</h3>
                <div className="encryption-grid">
                  {Object.entries(encryptionStatus).map(([key, status]) => (
                    <div key={key} className="encryption-item">
                      <span className="encryption-label">
                        {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                      </span>
                      <div className="encryption-status">
                        <CheckCircle className="encryption-status-icon" />
                        <span className="encryption-status-text">Active</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="content-card">
                <h3 className="card-title">Security Policies</h3>
                <div className="security-policies-list">
                  <div className="policy-item">
                    <span className="policy-label">Password Requirements</span>
                    <span className="policy-value">8+ chars, mixed case, numbers, symbols</span>
                  </div>
                  <div className="policy-item">
                    <span className="policy-label">Session Timeout</span>
                    <span className="policy-value">30 minutes</span>
                  </div>
                  <div className="policy-item">
                    <span className="policy-label">Max Login Attempts</span>
                    <span className="policy-value">3 attempts</span>
                  </div>
                  <div className="policy-item">
                    <span className="policy-label">Rate Limiting</span>
                    <span className="policy-value">10 requests/minute</span>
                  </div>
                  <div className="policy-item">
                    <span className="policy-label">2FA Requirement</span>
                    <span className="policy-value">Admin accounts only</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {selectedTab === 'threats' && (
            <div className="threats-content">
              <h2 className="section-title">Threat Analysis</h2>

              <div className="stats-grid small">
                <StatCard icon={Bug} title="Malware Detected" value="12" color="red" />
                <StatCard icon={Target} title="Intrusion Attempts" value="28" color="yellow" />
                <StatCard icon={Database} title="SQL Injections Blocked" value={realTimeStats.sqlInjectionBlocked} color="red" />
                <StatCard icon={Shield} title="XSS Attacks Blocked" value={realTimeStats.xssAttemptsBlocked} color="red" />
              </div>

              <div className="content-card">
                <h3 className="card-title">Detailed Threat Log</h3>
                <div className="threats-list">
                  {threats.map((threat) => (
                    <div key={threat.id} className="threat-alert">
                      <div className="threat-content">
                        <div className="threat-info">
                          <div className={`threat-status ${threat.status.toLowerCase()}`}></div>
                          <div className="threat-details">
                            <h4 className="threat-type">{threat.type}</h4>
                            <p className="threat-source"><strong>Source:</strong> {threat.source}</p>
                            <p className="threat-source"><strong>Time:</strong> {threat.time}</p>
                            {threat.query && (
                              <p className="threat-source">
                                <strong>Attack Vector:</strong> <code className="threat-code">{threat.query}</code>
                              </p>
                            )}
                            {threat.payload && (
                              <p className="threat-source">
                                <strong>Payload:</strong> <code className="threat-code">{threat.payload}</code>
                              </p>
                            )}
                            {threat.path && (
                              <p className="threat-source">
                                <strong>Path:</strong> <code className="threat-code">{threat.path}</code>
                              </p>
                            )}
                            <p className="threat-prevention">
                              <strong>Prevention:</strong> {threat.prevention}
                            </p>
                          </div>
                        </div>
                        <div className="threat-meta">
                          <span className={`severity-badge ${threat.severity.toLowerCase()}`}>
                            {threat.severity}
                          </span>
                          <span className="threat-time">{threat.time}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {selectedTab === 'network' && (
            <div className="network-content">
              <h2 className="section-title">Network Security</h2>

              <div className="content-grid">
                <div className="content-card">
                  <h3 className="card-title">Firewall Status</h3>
                  <div className="connection-list">
                    <div className="connection-item success">
                      <div className="connection-info">
                        <CheckCircle className="status-icon" />
                        <span className="connection-label">Web Application Firewall</span>
                      </div>
                      <span className="connection-status-text">ACTIVE</span>
                    </div>
                    <div className="connection-item success">
                      <div className="connection-info">
                        <CheckCircle className="status-icon" />
                        <span className="connection-label">DDoS Protection</span>
                      </div>
                      <span className="connection-status-text">ENABLED</span>
                    </div>
                    <div className="connection-item success">
                      <div className="connection-info">
                        <CheckCircle className="status-icon" />
                        <span className="connection-label">Intrusion Detection</span>
                      </div>
                      <span className="connection-status-text">MONITORING</span>
                    </div>
                  </div>
                </div>

                <div className="content-card">
                  <h3 className="card-title">SSL/TLS Configuration</h3>
                  <div className="ssl-config">
                    <div className="config-item">
                      <span className="config-label">Protocol Version</span>
                      <span className="config-value">TLS 1.3</span>
                    </div>
                    <div className="config-item">
                      <span className="config-label">Cipher Suite</span>
                      <span className="config-value">AES-256-GCM</span>
                    </div>
                    <div className="config-item">
                      <span className="config-label">Key Exchange</span>
                      <span className="config-value">ECDHE</span>
                    </div>
                    <div className="config-item">
                      <span className="config-label">Certificate Validity</span>
                      <span className="config-value-success">Valid (90 days)</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {selectedTab === 'analytics' && (
            <div className="analytics-content">
              <h2 className="section-title">Security Analytics</h2>

              <div className="content-grid">
                <div className="content-card">
                  <h3 className="card-title">Attack Patterns</h3>
                  <div className="analytics-metrics">
                    <div className="analytics-item">
                      <div className="analytics-header">
                        <span className="analytics-label">SQL Injection Attempts</span>
                        <span className="analytics-trend increase">↑ 15%</span>
                      </div>
                      <div className="progress-bar">
                        <div className="progress-fill red" style={{ width: '65%' }}></div>
                      </div>
                    </div>
                    <div className="analytics-item">
                      <div className="analytics-header">
                        <span className="analytics-label">XSS Attempts</span>
                        <span className="analytics-trend decrease">↓ 8%</span>
                      </div>
                      <div className="progress-bar">
                        <div className="progress-fill yellow" style={{ width: '35%' }}></div>
                      </div>
                    </div>
                    <div className="analytics-item">
                      <div className="analytics-header">
                        <span className="analytics-label">CSRF Attempts</span>
                        <span className="analytics-trend decrease">↓ 12%</span>
                      </div>
                      <div className="progress-bar">
                        <div className="progress-fill blue" style={{ width: '20%' }}></div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="content-card">
                  <h3 className="card-title">Response Metrics</h3>
                  <div className="response-metrics">
                    <div className="response-item">
                      <span className="response-label">Average Detection Time</span>
                      <span className="response-value"> 0.3s</span>
                    </div>
                    <div className="response-item">
                      <span className="response-label">Average Response Time</span>
                      <span className="response-value"> 1.2s</span>
                    </div>
                    <div className="response-item">
                      <span className="response-label">Threat Containment</span>
                      <span className="response-value"> 2.8s</span>
                    </div>
                    <div className="response-item">
                      <span className="response-label">False Positive Rate</span>
                      <span className="response-value-success"> 0.02%</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {selectedTab === 'logs' && (
            <div className="logs-content">
              <h2 className="section-title">Security Logs</h2>

              <div className="content-card">
                <h3 className="card-title">Recent Security Events</h3>
                <div className="security-logs-list">
                  {securityLogs.map((log, index) => (
                    <div key={index} className="security-log-item">
                      <div className="log-header">
                        <div className={`log-severity-dot ${log.severity}`}></div>
                        <span className="log-event-type">{log.event}</span>
                        <span className={`log-severity-badge ${log.severity}`}>
                          {log.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="log-details">{log.details}</p>
                      <div className="log-metadata">
                        <span>{new Date(log.timestamp).toLocaleString()}</span>
                        <span>Source: {log.source}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    );
  };

  return isLoggedIn ? (
    <Dashboard
      selectedTab={selectedTab}
      setSelectedTab={setSelectedTab}
    />
  ) : (
    <LoginScreen />
  );
};

export default CyberShieldPro;
