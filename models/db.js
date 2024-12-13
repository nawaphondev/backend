const mysql = require('mysql2');

const pool = mysql.createPool({
  host: 'localhost', // แก้ไขตามค่าของคุณ
  user: 'root',      // แก้ไขตามค่าของคุณ
  password: '12345678', // แก้ไขตามค่าของคุณ
  database: 'maintenance_system', // ชื่อฐานข้อมูลของคุณ
});

const promisePool = pool.promise();

module.exports = promisePool;
