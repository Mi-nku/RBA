const { query } = require('../database.js');

async function testConnection() {
    try {
        // 添加结果集验证
        const results = await query('SELECT NOW() AS `current_time`');

        console.log('原始结果:', results); // 调试输出

        if (results.length === 0) {
            throw new Error('查询返回空结果集');
        }

        console.log('✅ 数据库连接成功:', results[0].current_time);
    } catch (error) {
        console.error('❌ 数据库连接失败:', error);
    }
}

testConnection();