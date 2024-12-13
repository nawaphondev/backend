const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const router = express.Router();
const db = require('../models/db');

// Secret Key สำหรับ JWT
const JWT_SECRET = process.env.JWT_SECRET;

// API Login
router.post('/login', async (req, res) => {
  const { usernameOrEmail, password } = req.body;

  try {
    // ตรวจสอบผู้ใช้จากฐานข้อมูลโดยใช้ username หรือ email
    const [users] = await db.query(
      'SELECT * FROM users WHERE username = ? OR email = ?',
      [usernameOrEmail, usernameOrEmail]
    );

    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = users[0];

    // ตรวจสอบรหัสผ่าน
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // สร้าง JWT Token
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;

module.exports = router;
