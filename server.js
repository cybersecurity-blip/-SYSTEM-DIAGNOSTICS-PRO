require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000'
}));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// In-memory database (replace with real DB in production)
const users = [
  {
    id: 1,
    username: 'admin',
    passwordHash: bcrypt.hashSync('securepassword123', 10),
    role: 'admin'
  }
];

const systemStatus = {
  isOnline: true,
  firewallActive: true,
  remoteAccess: false,
  cpuThrottle: 'none',
  encryption: 'AES-256'
};

// JWT secret (use environment variable in production)
const JWT_SECRET = process.env.JWT_SECRET || 'your-very-secure-secret';

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Routes
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).send('Invalid credentials');
  
  const validPassword = await bcrypt.compare(password, user.passwordHash);
  if (!validPassword) return res.status(401).send('Invalid credentials');
  
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
  
  res.json({ token });
});

app.get('/api/system/status', authenticateToken, (req, res) => {
  res.json(systemStatus);
});

app.post('/api/system/shutdown', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  
  systemStatus.isOnline = false;
  res.json({ message: 'System shutdown initiated' });
  
  // In a real app, you'd actually shut down the system here
  setTimeout(() => {
    systemStatus.isOnline = true; // Simulate system coming back online
  }, 10000);
});

app.post('/api/system/toggle-firewall', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  
  systemStatus.firewallActive = !systemStatus.firewallActive;
  res.json({ 
    message: `Firewall ${systemStatus.firewallActive ? 'activated' : 'deactivated'}`,
    status: systemStatus 
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
