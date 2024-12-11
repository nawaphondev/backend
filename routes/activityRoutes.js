const express = require('express');
const logActivity = require('../controllers/activityController');

const router = express.Router();

// Example usage to log activity
router.post('/log', (req, res) => {
    const { user_id, action } = req.body;
    logActivity(user_id, action);
    res.status(200).json({ message: 'Activity logged successfully!' });
});

module.exports = router;
