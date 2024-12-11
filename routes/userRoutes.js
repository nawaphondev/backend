const express = require("express");
const multer = require("multer");
const userController = require("../controllers/userController");
const authorize = require("../middleware/authorize");
const authenticateToken = require("../middleware/auth")

const router = express.Router();

// Multer configuration
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 }, // ขนาดสูงสุด 2MB
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Only image files are allowed!'), false);
    }
    cb(null, true);
  },
});

// Middleware: Validate Registration Data
const validateRegistration = (req, res, next) => {
  const { username, email, password, confirmPassword } = req.body;
  if (!username || !email || !password || !confirmPassword) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }
  next();
};

// Middleware: Check File Provided
const checkFileProvided = (req, res, next) => {
  if (!req.file) {
    return res.status(400).json({ error: 'File not provided' });
  }
  next();
};

// User Registration Route
router.post(
  '/register',
  upload.single('profile_picture'),
  checkFileProvided,
  validateRegistration,
  async (req, res) => {
    try {
      await userController.registerUser(req, res);
    } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// Login Route
router.post("/login", userController.loginUser);

// Forgot Password Route
router.post("/forgot-password", userController.forgotPassword);

// Admin Only: Create User
router.post(
  "/create",
  authorize(["Admin", "Super User"]),
  userController.createUser
);

// Multer Error Handling
router.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.message });
  }
  if (err) {
    console.error("Unexpected Error:", err);
    return res.status(500).json({ error: 'Unexpected error occurred' });
  }
  next();
});

router.get("/me", authenticateToken, userController.getCurrentUser);

router.get("/:id/profile-picture", userController.getUserProfilePicture);


module.exports = router;
