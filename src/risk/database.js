const mysql = require('mysql2/promise');
const config = require('./config.js');

const pool = mysql.createPool(config.database);

async function query(sql, params) {
    const connection = await pool.getConnection();
    try {
        const [results] = await connection.execute(sql, params);
        return results;
    } finally {
        connection.release();
    }
}

module.exports = {
    query
};