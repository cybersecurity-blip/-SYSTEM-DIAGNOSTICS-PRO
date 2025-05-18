require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const morgan = require('morgan');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 5000;

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/system_diagnostics', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => logger.info('Connected to MongoDB'))
.catch(err => logger.error('MongoDB connection error:', err));

// MongoDB Schemas
const UserSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['admin', 'technician', 'viewer'], default: 'viewer' },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});

const SystemStatusSchema = new mongoose.Schema({
  isOnline: { type: Boolean, default: true },
  firewallActive: { type: Boolean, default: true },
  remoteAccess: { type: Boolean, default: false },
  cpuThrottle: { type: String, enum: ['none', 'low', 'medium', 'high'], default: 'none' },
  encryption: { type: String, default: 'AES-256' },
  lastUpdated: { type: Date, default: Date.now }
});

const LogSchema = new mongoose.Schema({
  action: String,
  userId: String,
  details: Object,
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const SystemStatus = mongoose.model('SystemStatus', SystemStatusSchema);
const Log = mongoose.model('Log', LogSchema);

// Initialize first admin user if none exists
async function initializeAdmin() {
  const adminExists = await User.findOne({ role: 'admin' });
  if (!adminExists) {
    const passwordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'securepassword123', 10);
    await User.create({
      username: process.env.ADMIN_USERNAME || 'admin',
      passwordHash,
      role: 'admin'
    });
    logger.info('Default admin user created');
  }
}

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  optionsSuccessStatus: 200
}));
app.use(express.json());
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api/', limiter);

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-very-secure-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

// Authentication middleware
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  
  if (!token) {
    logger.warn('Authentication attempt without token');
    return res.status(401).json({ error: 'Access token required' });
  }
  
  try {
    const user = jwt.verify(token, JWT_SECRET);
    const dbUser = await User.findById(user.id);
    
    if (!dbUser) {
      logger.warn(`Token valid but user not found: ${user.id}`);
      return res.status(403).json({ error: 'User not found' });
    }
    
    req.user = dbUser;
    next();
  } catch (err) {
    logger.warn(`Invalid token attempt: ${err.message}`);
    res.status(403).json({ error: 'Invalid or expired token' });
  }
}

function authorize(roles = []) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      logger.warn(`Unauthorized access attempt by ${req.user.username} to ${req.path}`);
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Logging middleware
async function logAction(req, res, next) {
  const oldJson = res.json;
  res.json = async (body) => {
    await Log.create({
      action: req.method + ' ' + req.path,
      userId: req.user?._id,
      details: {
        params: req.params,
        query: req.query,
        body: req.method === 'GET' ? undefined : req.body,
        response: body
      }
    });
    oldJson.call(res, body);
  };
  next();
}

// Routes
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) {
      logger.warn(`Login attempt for non-existent user: ${username}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) {
      logger.warn(`Failed login attempt for user: ${username}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    
    user.lastLogin = new Date();
    await user.save();
    
    logger.info(`Successful login for user: ${username}`);
    res.json({ token, user: { username: user.username, role: user.role } });
  } catch (err) {
    logger.error(`Login error: ${err.message}`);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/system/status', authenticateToken, logAction, async (req, res) => {
  try {
    const status = await SystemStatus.findOne().sort({ lastUpdated: -1 });
    res.json(status || await SystemStatus.create({}));
  } catch (err) {
    logger.error(`Status fetch error: ${err.message}`);
    res.status(500).json({ error: 'Failed to get system status' });
  }
});

app.post('/api/system/shutdown', authenticateToken, authorize(['admin']), logAction, async (req, res) => {
  try {
    await SystemStatus.updateOne({}, { isOnline: false, lastUpdated: new Date() });
    
    logger.warn(`System shutdown initiated by ${req.user.username}`);
    res.json({ message: 'System shutdown initiated' });
    
    // Simulate system coming back online after delay
    setTimeout(async () => {
      await SystemStatus.updateOne({}, { isOnline: true, lastUpdated: new Date() });
      logger.info('System automatically came back online');
    }, 10000);
  } catch (err) {
    logger.error(`Shutdown error: ${err.message}`);
    res.status(500).json({ error: 'Failed to initiate shutdown' });
  }
});

// Enhanced system controls
app.post('/api/system/toggle-firewall', authenticateToken, authorize(['admin', 'technician']), logAction, async (req, res) => {
  try {
    const status = await SystemStatus.findOne();
    const newStatus = !status.firewallActive;
    
    await SystemStatus.updateOne({}, { 
      firewallActive: newStatus,
      lastUpdated: new Date() 
    });
    
    logger.info(`Firewall ${newStatus ? 'activated' : 'deactivated'} by ${req.user.username}`);
    res.json({ 
      message: `Firewall ${newStatus ? 'activated' : 'deactivated'}`,
      firewallActive: newStatus 
    });
  } catch (err) {
    logger.error(`Firewall toggle error: ${err.message}`);
    res.status(500).json({ error: 'Failed to toggle firewall' });
  }
});

app.post('/api/system/set-throttle', authenticateToken, authorize(['admin']), logAction, async (req, res) => {
  try {
    const { level } = req.body;
    if (!['none', 'low', 'medium', 'high'].includes(level)) {
      return res.status(400).json({ error: 'Invalid throttle level' });
    }
    
    await SystemStatus.updateOne({}, { 
      cpuThrottle: level,
      lastUpdated: new Date() 
    });
    
    logger.info(`CPU throttle set to ${level} by ${req.user.username}`);
    res.json({ 
      message: `CPU throttle set to ${level}`,
      cpuThrottle: level 
    });
  } catch (err) {
    logger.error(`Throttle set error: ${err.message}`);
    res.status(500).json({ error: 'Failed to set CPU throttle' });
  }
});

// User management endpoints
app.get('/api/users', authenticateToken, authorize(['admin']), logAction, async (req, res) => {
  try {
    const users = await User.find({}, { passwordHash: 0 });
    res.json(users);
  } catch (err) {
    logger.error(`User list error: ${err.message}`);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

app.post('/api/users', authenticateToken, authorize(['admin']), logAction, async (req, res) => {
  try {
    const { username, password, role } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({
      username,
      passwordHash,
      role: role || 'viewer'
    });
    
    logger.info(`User ${username} created by ${req.user.username}`);
    res.status(201).json({
      _id: user._id,
      username: user.username,
      role: user.role,
      createdAt: user.createdAt
    });
  } catch (err) {
    logger.error(`User creation error: ${err.message}`);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.stack}`);
  res.status(500).json({ error: 'Internal server error' });
});

// Initialize and start server
async function startServer() {
  await initializeAdmin();
  
  app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
    console.log(`Server running on port ${PORT}`);
  });
}

startServer();
// Admin endpoints
app.get('/api/system/status', async (req, res) => {
  const status = await SystemStatus.findOne();
  res.json({
    maintenanceMode: status?.maintenanceMode || false,
    activeUsers: await User.countDocuments({ isActive: true }),
    // Add other status fields
  });
});

app.post('/api/system/maintenance', async (req, res) => {
  const current = await SystemStatus.findOne();
  const newMode = !current?.maintenanceMode;
  
  await SystemStatus.updateOne({}, {
    maintenanceMode: newMode,
    lastUpdated: new Date()
  }, { upsert: true });
  
  res.json({ success: true, maintenanceMode: newMode });
});

app.post('/api/system/throttle', async (req, res) => {
  const { percent } = req.body;
  await SystemStatus.updateOne({}, {
    cpuThrottle: Math.min(100, Math.max(0, percent)),
    lastUpdated: new Date()
  }, { upsert: true });
  
  res.json({ success: true });
});
