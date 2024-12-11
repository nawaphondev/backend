const db = require('../models/userModel');

exports.getMaintenanceReport = (req, res) => {
    const query = `
        SELECT Equipment.name, Maintenance.maintenance_date, Maintenance.status
        FROM Maintenance
        JOIN Equipment ON Maintenance.equipment_id = Equipment.id
        WHERE Maintenance.status = 'Scheduled'
        ORDER BY Maintenance.maintenance_date ASC;
    `;
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(200).json(results);
    });
};
