const sql = require('mssql');
require('dotenv').config();

// 支持Always Encrypted的SQL Server连接配置
const encryptedConfig = {
    user: process.env.SQLSERVER_USER || 'your_username',
    password: process.env.SQLSERVER_PASSWORD || 'your_password',
    server: process.env.SQLSERVER_HOST || 'your_rds_endpoint.sqlserver.rds.aliyuncs.com',
    port: parseInt(process.env.SQLSERVER_PORT) || 1433,
    database: process.env.SQLSERVER_DATABASE || 'your_database_name',
    options: {
        encrypt: true,
        trustServerCertificate: true,
        enableArithAbort: true,
        requestTimeout: 30000,
        connectionTimeout: 30000,
        // 启用Always Encrypted支持
        columnEncryptionSetting: 'Enabled',
        enclaveAttestationUrl: '', // 开发环境留空
        enclaveAttestationProtocol: 'None', // 不使用证明服务
        pool: {
            max: 10,
            min: 0,
            idleTimeoutMillis: 30000
        }
    }
};

class EncryptedSQLServerConnection {
    constructor() {
        this.pool = null;
        this.isConnected = false;
    }

    async connect() {
        try {
            console.log('正在连接支持Always Encrypted的SQL Server...');
            this.pool = await sql.connect(encryptedConfig);
            this.isConnected = true;
            console.log('✅ 成功连接到支持Always Encrypted的SQL Server');
            
            await this.checkEnclaveStatus();
            return true;
        } catch (error) {
            console.error('❌ Always Encrypted连接失败:', error.message);
            this.isConnected = false;
            throw error;
        }
    }

    async checkEnclaveStatus() {
        try {
            const result = await this.query(`
                SELECT [name], [value], [value_in_use] 
                FROM sys.configurations 
                WHERE [name] = 'column encryption enclave type'
            `);
            
            if (result.recordset.length > 0) {
                const enclaveConfig = result.recordset[0];
                console.log('🔐 Enclave状态:', enclaveConfig);
                
                if (enclaveConfig.value_in_use === 1) {
                    console.log('✅ VBS Enclave已启用');
                } else {
                    console.warn('⚠️ VBS Enclave未启用');
                }
            }
        } catch (error) {
            console.error('检查Enclave状态失败:', error.message);
        }
    }

    async query(queryText, params = []) {
        if (!this.isConnected) {
            throw new Error('数据库未连接');
        }

        try {
            const request = this.pool.request();
            
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

    async queryWithParams(queryText, params = {}) {
        if (!this.isConnected) {
            throw new Error('数据库未连接');
        }

        try {
            const request = this.pool.request();
            
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

    async insertEncryptedUser(userData) {
        const insertSQL = `
            INSERT INTO [dbo].[users_encrypted] 
            ([id], [username], [email], [password], [createdAt], [lastLogin], [loginHistory], [isAdmin], [sessionId])
            VALUES (@id, @username, @email, @password, @createdAt, @lastLogin, @loginHistory, @isAdmin, @sessionId)
        `;

        try {
            const request = this.pool.request();
            
            // 明确指定参数类型，特别是对加密列
            request.input('id', sql.NVarChar(50), userData.id);
            request.input('username', sql.NVarChar(50), userData.username);
            request.input('email', sql.NVarChar(255), userData.email);
            request.input('password', sql.NVarChar(255), userData.password);
            request.input('createdAt', sql.DateTime2, userData.createdAt);
            request.input('lastLogin', sql.DateTime2, userData.lastLogin);
            request.input('loginHistory', sql.NVarChar(sql.MAX), JSON.stringify(userData.loginHistory || []));
            request.input('isAdmin', sql.Bit, userData.isAdmin || false);
            request.input('sessionId', sql.NVarChar(255), userData.sessionId);

            const result = await request.query(insertSQL);
            console.log('✅ 加密用户数据插入成功');
            return result;
        } catch (error) {
            console.error('❌ 插入加密用户数据失败:', error.message);
            throw error;
        }
    }

    async findUserByUsername(username) {
        const querySQL = `
            SELECT [id], [username], [email], [password], [createdAt], [lastLogin], 
                   [loginHistory], [isAdmin], [sessionId]
            FROM [dbo].[users_encrypted]
            WHERE [username] = @username
        `;

        try {
            const request = this.pool.request();
            // 明确指定参数类型
            request.input('username', sql.NVarChar(50), username);
            
            const result = await request.query(querySQL);
            
            if (result.recordset.length > 0) {
                const user = result.recordset[0];
                if (user.loginHistory) {
                    user.loginHistory = JSON.parse(user.loginHistory);
                }
                return user;
            }
            return null;
        } catch (error) {
            console.error('❌ 查询加密用户数据失败:', error.message);
            throw error;
        }
    }

    async close() {
        try {
            if (this.pool) {
                await this.pool.close();
                this.isConnected = false;
                console.log('✅ 数据库连接已关闭');
            }
        } catch (error) {
            console.error('❌ 关闭数据库连接失败:', error.message);
        }
    }
}

module.exports = { EncryptedSQLServerConnection }; 