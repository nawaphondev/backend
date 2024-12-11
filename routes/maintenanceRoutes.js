const express = require('express');
const maintenanceController = require('../controllers/maintenanceController');
const authorize = require('../middleware/authorize');

const router = express.Router();

// Maintenance routes
router.post('/add', authorize(['Admin', 'Super User']), maintenanceController.createMaintenance);
router.get('/all', maintenanceController.getMaintenance);
router.put('/update', authorize(['Admin', 'Super User']), maintenanceController.updateMaintenance);
router.delete('/delete/:id', authorize(['Admin', 'Super User']), maintenanceController.deleteMaintenance);

module.exports = router;
