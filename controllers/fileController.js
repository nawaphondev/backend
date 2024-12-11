const db = require('../models/userModel');

// อัปโหลดไฟล์สำหรับอุปกรณ์
exports.uploadEquipmentFile = (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    const file = req.file.buffer.toString('base64');
    const { equipmentId } = req.body;

    const query = 'UPDATE Equipment SET file = ? WHERE id = ?';
    db.query(query, [file, equipmentId], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(200).json({ message: 'File uploaded successfully!' });
    });
};