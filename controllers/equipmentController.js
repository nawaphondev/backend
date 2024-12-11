const db = require('../models/userModel');

// Create equipment
exports.createEquipment = (req, res) => {
    const { name, serial_number, status, installation_date } = req.body;
    const query = 'INSERT INTO Equipment (name, serial_number, status, installation_date) VALUES (?, ?, ?, ?)';
    
    db.query(query, [name, serial_number, status, installation_date], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ message: "Equipment added successfully!" });
    });
};

// Get all equipment
exports.getEquipment = (req, res) => {
    const query = 'SELECT * FROM Equipment';
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(200).json(results);
    });
};

// Update equipment status or details
exports.updateEquipment = (req, res) => {
    const { id, name, serial_number, status, installation_date } = req.body;
    const query = 'UPDATE Equipment SET name = ?, serial_number = ?, status = ?, installation_date = ? WHERE id = ?';
    
    db.query(query, [name, serial_number, status, installation_date, id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(200).json({ message: "Equipment updated successfully!" });
    });
};

// Delete equipment
exports.deleteEquipment = (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM Equipment WHERE id = ?';
    
    db.query(query, [id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(200).json({ message: "Equipment deleted successfully!" });
    });
};
