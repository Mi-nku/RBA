const sql = require('mssql');
require('dotenv').config();

// 阿里云RDS SQL Server连接配置
const config = {
    user: process.env.SQLSERVER_USER || 'your_username',
    password: process.env.SQLSERVER_PASSWORD || 'your_password',
    server: process.env.SQLSERVER_HOST || 'your_rds_endpoint.sqlserver.rds.aliyuncs.com',
    port: parseInt(process.env.SQLSERVER_PORT) || 1433,
    database: process.env.SQLSERVER_DATABASE || 'your_database_name',
    options: {
        encrypt: true, // 阿里云RDS需要加密连接
        trustServerCertificate: true, // 信任自签名证书（阿里云RDS使用自签名证书）
        enableArithAbort: true,
        requestTimeout: 30000, // 30秒超时
        connectionTimeout: 30000,
        pool: {
            max: 10,
            min: 0,
            idleTimeoutMillis: 30000
        }
    }
};

class SQLServerConnection {
    constructor() {
        this.pool = null;
        this.isConnected = false;
    }

    /**
     * 连接到SQL Server数据库
     */
    async connect() {
        try {
            console.log('正在连接阿里云RDS SQL Server...');
            this.pool = await sql.connect(config);
            this.isConnected = true;
            console.log('✅ 成功连接到阿里云RDS SQL Server');
            
            // 测试连接
            await this.testConnection();
            return true;
        } catch (error) {
            console.error('❌ 连接失败:', error.message);
            this.isConnected = false;
            throw error;
        }
    }

    /**
     * 测试数据库连接
     */
    async testConnection() {
        try {
            const result = await this.query('SELECT @@VERSION as version, GETDATE() as server_time');
            console.log('🔧 数据库版本:', result.recordset[0].version);
            console.log('⏰ 当前时间:', result.recordset[0].server_time);
        } catch (error) {
            console.error('连接测试失败:', error.message);
            throw error;
        }
    }

    /**
     * 执行SQL查询
     * @param {string} queryText - SQL查询语句
     * @param {Array} params - 查询参数
     */
    async query(queryText, params = []) {
        if (!this.isConnected) {
            throw new Error('数据库未连接');
        }

        try {
            const request = this.pool.request();
            
            // 添加参数
            if (params && params.length > 0) {
                params.forEach((param, index) => {
                    request.input(`param${index}`, param);
                });
            }

            const result = await request.query(queryText);
            return result;
        } catch (error) {
            console.error('查询执行失败:', error.message);
            throw error;
        }
    }

    /**
     * 执行带参数的查询（更安全的方式）
     * @param {string} queryText - SQL查询语句，使用@param0, @param1等占位符
     * @param {Object} params - 参数对象
     */
    async queryWithParams(queryText, params = {}) {
        if (!this.isConnected) {
            throw new Error('数据库未连接');
        }

        try {
            const request = this.pool.request();
            
            // 添加命名参数
            for (const [key, value] of Object.entries(params)) {
                request.input(key, value);
            }

            const result = await request.query(queryText);
            return result;
        } catch (error) {
            console.error('参数化查询执行失败:', error.message);
            throw error;
        }
    }

    /**
     * 创建表（示例）
     */
    async createRiskLogsTable() {
        const createTableSQL = `
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='risk_logs' AND xtype='U')
            CREATE TABLE risk_logs (
                id INT IDENTITY(1,1) PRIMARY KEY,
                user_id NVARCHAR(50) NOT NULL,
                ip_address NVARCHAR(45) NOT NULL,
                geo_data NVARCHAR(MAX),
                risk_score DECIMAL(5,4) NOT NULL,
                user_agent NVARCHAR(MAX),
                rtt DECIMAL(10,3),
                created_at DATETIME2 DEFAULT GETDATE()
            );
        `;

        try {
            await this.query(createTableSQL);
            console.log('✅ risk_logs表创建成功或已存在');
        } catch (error) {
            console.error('❌ 创建表失败:', error.message);
            throw error;
        }
    }

    /**
     * 插入风险日志
     * @param {Object} logData - 日志数据
     */
    async insertRiskLog(logData) {
        const insertSQL = `
            INSERT INTO risk_logs (user_id, ip_address, geo_data, risk_score, user_agent, rtt)
            VALUES (@user_id, @ip_address, @geo_data, @risk_score, @user_agent, @rtt)
        `;

        try {
            const result = await this.queryWithParams(insertSQL, {
                user_id: logData.user_id,
                ip_address: logData.ip_address,
                geo_data: JSON.stringify(logData.geo_data),
                risk_score: logData.risk_score,
                user_agent: logData.user_agent,
                rtt: logData.rtt
            });

            console.log('✅ 风险日志插入成功');
            return result;
        } catch (error) {
            console.error('❌ 插入风险日志失败:', error.message);
            throw error;
        }
    }

    /**
     * 查询用户风险历史
     * @param {string} userId - 用户ID
     * @param {number} limit - 限制数量
     */
    async getUserRiskHistory(userId, limit = 50) {
        const querySQL = `
            SELECT TOP (@limit) 
                id, ip_address, geo_data, risk_score, user_agent, rtt, created_at
            FROM risk_logs
            WHERE user_id = @user_id
            ORDER BY created_at DESC
        `;

        try {
            const result = await this.queryWithParams(querySQL, {
                user_id: userId,
                limit: limit
            });

            return result.recordset;
        } catch (error) {
            console.error('❌ 查询用户风险历史失败:', error.message);
            throw error;
        }
    }

    /**
     * 获取全局登录统计
     */
    async getGlobalStats() {
        const statsSQL = `
            SELECT 
                COUNT(*) as total_logins,
                COUNT(DISTINCT user_id) as unique_users,
                COUNT(DISTINCT ip_address) as unique_ips,
                AVG(risk_score) as avg_risk_score,
                MAX(created_at) as last_login
            FROM risk_logs
        `;

        try {
            const result = await this.query(statsSQL);
            return result.recordset[0];
        } catch (error) {
            console.error('❌ 获取全局统计失败:', error.message);
            throw error;
        }
    }

    /**
     * 关闭数据库连接
     */
    async close() {
        try {
            if (this.pool) {
                await this.pool.close();
                this.isConnected = false;
                console.log('🔌 数据库连接已关闭');
            }
        } catch (error) {
            console.error('关闭连接失败:', error.message);
        }
    }
}

// 使用示例
async function main() {
    const db = new SQLServerConnection();
    
    try {
        // 连接数据库
        await db.connect();
        
        // 创建表
        await db.createRiskLogsTable();
        
        // 插入示例数据
        await db.insertRiskLog({
            user_id: 'test_user_123',
            ip_address: '192.168.1.100',
            geo_data: { cc: 'CN', asn: 'AS4134' },
            risk_score: 0.35,
            user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            rtt: 45.23
        });
        
        // 查询用户历史
        const history = await db.getUserRiskHistory('test_user_123', 10);
        console.log('用户历史记录:', history);
        
        // 获取全局统计
        const stats = await db.getGlobalStats();
        console.log('全局统计:', stats);
        
    } catch (error) {
        console.error('操作失败:', error.message);
    } finally {
        // 关闭连接
        await db.close();
    }
}

// 导出类和配置
module.exports = {
    SQLServerConnection,
    config
};

// 如果直接运行此脚本则执行示例
if (require.main === module) {
    main().catch(console.error);
}