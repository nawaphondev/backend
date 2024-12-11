const express = require('express');
const authorize = require('../middleware/authorize');
const equipmentController = require('../controllers/equipmentController');

const router = express.Router();

// Equipment routes
router.post('/add', equipmentController.createEquipment);
router.get('/all', equipmentController.getEquipment);
router.put('/update', equipmentController.updateEquipment);
router.delete('/delete/:id', equipmentController.deleteEquipment);

// Routes that only Admins can access
router.post('/add', authorize(['Admin']), equipmentController.createEquipment);
router.put('/update', authorize(['Admin']), equipmentController.updateEquipment);

module.exports = router;
