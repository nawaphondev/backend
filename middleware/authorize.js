const jwt = require("jsonwebtoken");

const authorize = (allowedLevels) => {
  return (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Extract Bearer token

    if (!token) {
      return res.status(403).json({ error: "No token provided" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        console.error("Token verification failed:", err.message);
        return res.status(403).json({ error: "Invalid or expired token" });
      }

      const userLevel = decoded.userLevel; // ดึง userLevel จาก JWT Payload
      console.log(`User level: ${userLevel}, Required levels: ${allowedLevels}`);

      if (!allowedLevels.includes(userLevel)) {
        return res.status(403).json({
          error: "Insufficient permissions",
          requiredLevels: allowedLevels,
          userLevel: userLevel,
        });
      }

      req.user = decoded; // Attach user info to req for further processing
      next();
    });
  };
};

module.exports = authorize;
