const express = require('express');
const multer = require('multer');
const fileController = require('../controllers/fileController');
const authorize = require('../middleware/authorize');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// Route สำหรับอัปโหลดไฟล์ อนุญาตเฉพาะ Admin
router.post('/upload', authorize(['Admin']), upload.single('file'), fileController.uploadEquipmentFile);

module.exports = router;
