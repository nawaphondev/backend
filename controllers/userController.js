const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const db = require("../models/userModel");
const multer = require("multer");

// Multer setup for profile picture upload
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Login user (using username or email)
exports.loginUser = async (req, res) => {
  const { usernameOrEmail, password } = req.body;

  const query =
    "SELECT id, username, user_level, password FROM Users WHERE username = ? OR email = ? LIMIT 1";
  db.query(query, [usernameOrEmail, usernameOrEmail], async (err, results) => {
    if (err) {
      console.error("Database error:", err.message);
      return res.status(500).json({ error: "Database error occurred" });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = results[0];

    // ตรวจสอบรหัสผ่าน
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    // ตรวจสอบว่ามี user_level หรือไม่
    if (!user.user_level) {
      console.error("User level missing for user:", user.username);
      return res.status(500).json({ error: "User level is missing in database" });
    }

    // สร้าง JWT พร้อม user_level
    const token = jwt.sign(
      {
        userId: user.id,          // ฝัง userId
        userLevel: user.user_level, // ฝัง user_level ใน Payload
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    console.log("JWT Payload:", { userId: user.id, userLevel: user.user_level }); // Log เพื่อตรวจสอบ
    res.json({ token });
  });
};

// Register a new user with profile picture upload
exports.registerUser = async (req, res) => {
  try {
    const {
      username,
      email,
      password,
      confirmPassword,
      userLevel = "User",
      status = "Active",
    } = req.body;

    if (password !== confirmPassword) {
      return res.status(400).json({ error: "Passwords do not match" });
    }

    // แปลงรูปภาพเป็น Base64
    const profilePicture = req.file ? req.file.buffer.toString("base64") : null;

    const checkQuery = "SELECT * FROM Users WHERE username = ? OR email = ?";
    db.query(checkQuery, [username, email], async (err, results) => {
      if (err) {
        console.error("Database Error:", err);
        return res.status(500).json({ error: err.message });
      }
      if (results.length > 0) {
        return res
          .status(400)
          .json({ error: "Username or email already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const query =
        "INSERT INTO Users (username, email, password, profile_picture, user_level, status) VALUES (?, ?, ?, ?, ?, ?)";
      db.query(
        query,
        [username, email, hashedPassword, profilePicture, userLevel, status],
        (err, result) => {
          if (err) {
            console.error("Insert Error:", err);
            return res.status(500).json({ error: err.message });
          }
          res.status(201).json({ message: "User registered successfully!" });
        }
      );
    });
  } catch (error) {
    console.error("Unexpected Error in Controller:", error.message);
    res
      .status(500)
      .json({ error: error.message || "Unexpected error occurred" });
  }
};

// Get user profile picture
exports.getUserProfilePicture = (req, res) => {
  const userId = req.params.id;
  const query = "SELECT profile_picture FROM Users WHERE id = ?";

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).json({ error: "Database error occurred" });
    }

    if (results.length === 0 || !results[0].profile_picture) {
      return res.status(404).json({ error: "Profile picture not found" });
    }

    const profilePicturePath = `uploads/${results[0].profile_picture}`;
    res.sendFile(profilePicturePath, { root: "." }, (err) => {
      if (err) {
        console.error("File Error:", err);
        res.status(500).json({ error: "Error sending file" });
      }
    });
  });
};

// Create a new user (Admin or Super User only)
exports.createUser = async (req, res) => {
  try {
    const {
      username,
      email,
      password,
      userLevel = "User",
      status = "Active",
    } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const query =
      "INSERT INTO Users (username, email, password, user_level, status) VALUES (?, ?, ?, ?, ?)";
    db.query(
      query,
      [username, email, hashedPassword, userLevel, status],
      (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ message: "User created successfully!" });
      }
    );
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Forgot password (send reset email to Admin)
exports.forgotPassword = (req, res) => {
  const { email } = req.body;

  const query = "SELECT * FROM Users WHERE email = ?";
  db.query(query, [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0)
      return res.status(404).json({ error: "Email not found" });

    const user = results[0];
    sendResetEmail(user.email);
    res.json({ message: "Password reset request sent to Admin." });
  });
};

// Send password reset email to Admin
const sendResetEmail = (userEmail) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.MAIL_USER,
    to: "admin@example.com",
    subject: "Password Reset Request",
    text: `User with email ${userEmail} has requested a password reset.`,
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.log("Error sending email:", err);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
};

exports.getCurrentUser = (req, res) => {
  try {
    const userId = req.user.userId; // Extract user ID from JWT
    const query =
      "SELECT id, username, email, profile_picture FROM Users WHERE id = ?";

    db.query(query, [userId], (err, results) => {
      if (err) {
        console.error("Database Error:", err);
        return res.status(500).json({ error: "Database error occurred" });
      }

      if (results.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      const user = results[0];

      // Convert profile_picture from Buffer to Base64
      const profilePictureBase64 = user.profile_picture
        ? `data:image/jpeg;base64,${user.profile_picture.toString("base64")}`
        : null;

      res.json({
        id: user.id,
        username: user.username,
        email: user.email,
        profilePicture: profilePictureBase64,
      });
    });
  } catch (error) {
    console.error("Unexpected Error in Controller:", error.message);
    res.status(500).json({ error: "Unexpected error occurred" });
  }
};

// Read a user by ID
exports.readUser = (req, res) => {
  const userId = req.params.id;
  const query =
    "SELECT id, username, email, profile_picture, user_level, status FROM Users WHERE id = ?";

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).json({ error: "Database error occurred" });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = results[0];

    // แปลงรูปโปรไฟล์เป็น Base64
    const profilePictureBase64 = user.profile_picture
      ? `data:image/jpeg;base64,${user.profile_picture.toString("base64")}`
      : null;

    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      profile_picture: profilePictureBase64,
      user_level: user.user_level,
      status: user.status,
    });
  });
};

exports.getUserProfilePicture = (req, res) => {
  const userId = req.params.id;
  const query = "SELECT profile_picture FROM Users WHERE id = ?";

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).json({ error: "Database error occurred" });
    }

    if (results.length === 0 || !results[0].profile_picture) {
      return res.status(404).json({ error: "Profile picture not found" });
    }

    // แปลง Buffer เป็น Base64
    const base64Image = `data:image/jpeg;base64,${results[0].profile_picture.toString(
      "base64"
    )}`;

    // ส่ง Base64 กลับไป
    res.json({ profile_picture: base64Image });
  });
};

// Get all users
exports.getAllUsers = (req, res) => {
  const query = "SELECT id, username, email, user_level, status FROM Users";

  db.query(query, (err, results) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).json({ error: "Database error occurred" });
    }

    res.json(results);
  });
};

// Update user details
exports.updateUser = (req, res) => {
  const userId = req.params.id;
  const { username, email, userLevel, status } = req.body;
  const query =
    "UPDATE Users SET username = ?, email = ?, user_level = ?, status = ? WHERE id = ?";

  db.query(
    query,
    [username, email, userLevel, status, userId],
    (err, result) => {
      if (err) {
        console.error("Database Error:", err);
        return res.status(500).json({ error: "Database error occurred" });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      res.json({ message: "User updated successfully!" });
    }
  );
};

// Delete a user by ID
exports.deleteUser = (req, res) => {
  const userId = req.params.id;
  const query = "DELETE FROM Users WHERE id = ?";

  db.query(query, [userId], (err, result) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).json({ error: "Database error occurred" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "User deleted successfully!" });
  });
};
