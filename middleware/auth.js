const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extract Bearer token

  if (!token) {
    return res.status(403).json({ error: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('Invalid token:', err.message); // Log for debugging
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    req.user = decoded; // Attach decoded token payload to req.user
    next();
  });
};

module.exports = authenticateToken;
