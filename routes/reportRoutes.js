const express = require('express');
const reportController = require('../controllers/reportController');
const authorize = require('../middleware/authorize');

const router = express.Router();

// เส้นทางสำหรับการสร้างรายงานการบำรุงรักษา
router.get('/maintenance', authorize(['Admin']), reportController.getMaintenanceReport);

module.exports = router;
