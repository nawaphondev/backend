// Get status of an equipment
exports.getStatus = (req, res) => {
    const query = 'SELECT * FROM Status WHERE equipment_id = ?';
    db.query(query, [req.params.equipment_id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(200).json(results);
    });
};

// Update equipment status
exports.updateStatus = (req, res) => {
    const { equipment_id, status } = req.body;
    const query = 'INSERT INTO Status (equipment_id, status) VALUES (?, ?)';
    
    db.query(query, [equipment_id, status], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(200).json({ message: "Equipment status updated successfully!" });
    });
};
