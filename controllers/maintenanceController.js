// Create maintenance record
exports.createMaintenance = (req, res) => {
    const { equipment_id, maintenance_date, details, status } = req.body;
    const query = 'INSERT INTO Maintenance (equipment_id, maintenance_date, details, status) VALUES (?, ?, ?, ?)';
    
    db.query(query, [equipment_id, maintenance_date, details, status], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ message: "Maintenance record added successfully!" });
    });
};

// Get all maintenance records
exports.getMaintenance = (req, res) => {
    const query = 'SELECT * FROM Maintenance';
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(200).json(results);
    });
};

// Update maintenance status or details
exports.updateMaintenance = (req, res) => {
    const { id, equipment_id, maintenance_date, details, status } = req.body;
    const query = 'UPDATE Maintenance SET equipment_id = ?, maintenance_date = ?, details = ?, status = ? WHERE id = ?';
    
    db.query(query, [equipment_id, maintenance_date, details, status, id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(200).json({ message: "Maintenance record updated successfully!" });
    });
};

// Delete maintenance record
exports.deleteMaintenance = (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM Maintenance WHERE id = ?';
    
    db.query(query, [id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(200).json({ message: "Maintenance record deleted successfully!" });
    });
};
