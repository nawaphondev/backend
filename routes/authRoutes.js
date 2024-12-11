const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const router = express.Router();
const db = require('./db'); // การเชื่อมต่อฐานข้อมูล

// Secret Key สำหรับ JWT
const JWT_SECRET = 'your_secret_key';

// API Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // ตรวจสอบผู้ใช้จากฐานข้อมูล
    const [user] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

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
