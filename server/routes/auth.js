const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();

// Admin login endpoint
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Hardcoded admin credentials (replace these!)
    const ADMIN_CREDENTIALS = {
      username: "admin",
      password: "YourSecurePassword123!" // << CHANGE THIS
    };

    // Check credentials
    if (username === ADMIN_CREDENTIALS.username && 
        password === ADMIN_CREDENTIALS.password) {
      
      // Create or update admin user
      let user = await User.findOne({ username });
      if (!user) {
        const hashedPassword = await bcrypt.hash(ADMIN_CREDENTIALS.password, 10);
        user = await User.create({
          username: ADMIN_CREDENTIALS.username,
          passwordHash: hashedPassword,
          role: 'admin'
        });
      }

      // Generate token
      const token = jwt.sign(
        { id: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
