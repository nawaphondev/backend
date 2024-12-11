// Log user activity
exports.logActivity = (user_id, action) => {
    const query = 'INSERT INTO Activity_Log (user_id, action) VALUES (?, ?)';
    
    db.query(query, [user_id, action], (err, result) => {
        if (err) console.error('Error logging activity:', err);
    });
};
