const jwt = require('jsonwebtoken');

const authorize = (roles) => {
    return (req, res, next) => {
        const token = req.headers['authorization']?.split(' ')[1]; // Bearer token
        if (!token) return res.status(403).json({ error: 'No token provided' });

        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) return res.status(403).json({ error: 'Failed to authenticate token' });
            
            const userRole = decoded.role;
            if (!roles.includes(userRole)) {
                return res.status(403).json({ error: 'Insufficient permissions' });
            }

            next();
        });
    };
};

module.exports = authorize;
