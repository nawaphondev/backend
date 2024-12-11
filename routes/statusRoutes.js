const express = require('express');
const statusController = require('../controllers/statusController');

const router = express.Router();

// Status routes
router.get('/status/:equipment_id', statusController.getStatus);
router.put('/update-status', statusController.updateStatus);

module.exports = router;
