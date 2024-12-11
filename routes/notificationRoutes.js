const express = require('express');
const sendMaintenanceReminder = require('../controllers/notificationController');

const router = express.Router();

// Route for sending maintenance reminders
router.post('/send-reminder', (req, res) => {
    const { email, equipmentName, maintenanceDate } = req.body;
    sendMaintenanceReminder(email, equipmentName, maintenanceDate);
    res.status(200).json({ message: 'Reminder email sent!' });
});

module.exports = router;
