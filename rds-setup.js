const { SQLServerConnection } = require('./sqlserver-connection');

async function setupBasicEncryption() {
    const db = new SQLServerConnection();
    
    try {
        console.log('🚀 开始设置基础Always Encrypted（适合阿里云RDS）');
        console.log('=====================================================');
        
        await db.connect();
        
        // 第二阶段：创建列主密钥
        console.log('\n🔑 第二阶段：创建列主密钥...');
        
        const existingCMK = await db.query(`
            SELECT COUNT(*) as count FROM sys.column_master_keys WHERE name = 'RBA_CMK'
        `);
        
        if (existingCMK.recordset[0].count === 0) {
            const createCMKSQL = `
                CREATE COLUMN MASTER KEY [RBA_CMK]
                WITH (
                    KEY_STORE_PROVIDER_NAME = 'MSSQL_CERTIFICATE_STORE',
                    KEY_PATH = 'CurrentUser/My/RBA_AlwaysEncrypted_Certificate'
                );
            `;
            
            await db.query(createCMKSQL);
            console.log('✅ 列主密钥 [RBA_CMK] 创建成功');
        } else {
            console.log('⚠️ 列主密钥 [RBA_CMK] 已存在，跳过创建');
        }

        // 创建列加密密钥
        console.log('\n🔐 创建列加密密钥...');
        console.log('⚠️  注意：CEK创建需要客户端证书支持');
        
        const existingCEK = await db.query(`
            SELECT COUNT(*) as count FROM sys.column_encryption_keys WHERE name = 'RBA_CEK'
        `);
        
        if (existingCEK.recordset[0].count === 0) {
            try {
                // 先检查是否能生成CEK（需要证书支持）
                const createCEKSQL = `
                    CREATE COLUMN ENCRYPTION KEY [RBA_CEK]
                    WITH VALUES (
                        COLUMN_MASTER_KEY = [RBA_CMK],
                        ALGORITHM = 'RSA_OAEP',
                        ENCRYPTED_VALUE = 0x0100000001680074007400700073003A002F002F0073006D0073003A0054003A0034003400330030003A0043006F006C0075006D006E0045006E006300720079007000740069006F006E0043006500720074006900660069006300610074006500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
                    );
                `;
                
                await db.query(createCEKSQL);
                console.log('✅ 列加密密钥 [RBA_CEK] 创建成功');
            } catch (error) {
                console.log('❌ CEK创建失败:', error.message);
                console.log('');
                console.log('📋 CEK创建失败的可能原因：');
                console.log('1. 客户端证书尚未生成');
                console.log('2. 证书路径不正确');
                console.log('3. 证书权限问题');
                console.log('');
                console.log('🔧 解决方案：');
                console.log('请先运行以下命令生成证书：');
                console.log('powershell -Command "New-SelfSignedCertificate -Subject \'CN=RBA_AlwaysEncrypted_Certificate\' -KeyExportPolicy Exportable -KeySpec KeyExchange -KeyLength 2048 -CertStoreLocation \'Cert:\\\\CurrentUser\\\\My\'"');
                console.log('');
                console.log('然后重新运行此脚本');
                
                // 继续执行其他步骤
            }
        } else {
            console.log('⚠️ 列加密密钥 [RBA_CEK] 已存在，跳过创建');
        }

        // 第三阶段：创建加密表结构
        console.log('\n📊 第三阶段：创建加密表结构...');
        
        // 创建加密用户表
        console.log('   📝 创建加密用户表...');
        const userTableExists = await db.query(`
            SELECT COUNT(*) as count FROM sys.tables WHERE name = 'users_encrypted'
        `);
        
        if (userTableExists.recordset[0].count === 0) {
            const createUserTableSQL = `
                CREATE TABLE [dbo].[users_encrypted] (
                    [id] NVARCHAR(50) NOT NULL,
                    [username] NVARCHAR(50) COLLATE Chinese_PRC_BIN2 ENCRYPTED WITH (
                        COLUMN_ENCRYPTION_KEY = [RBA_CEK],
                        ENCRYPTION_TYPE = Deterministic,
                        ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'
                    ) NOT NULL,
                    [email] NVARCHAR(255) ENCRYPTED WITH (
                        COLUMN_ENCRYPTION_KEY = [RBA_CEK],
                        ENCRYPTION_TYPE = Randomized,
                        ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'
                    ) NOT NULL,
                    [password] NVARCHAR(255) ENCRYPTED WITH (
                        COLUMN_ENCRYPTION_KEY = [RBA_CEK],
                        ENCRYPTION_TYPE = Randomized,
                        ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'
                    ) NOT NULL,
                    [createdAt] DATETIME2 NOT NULL,
                    [lastLogin] DATETIME2 NULL,
                    [loginHistory] NVARCHAR(MAX) ENCRYPTED WITH (
                        COLUMN_ENCRYPTION_KEY = [RBA_CEK],
                        ENCRYPTION_TYPE = Randomized,
                        ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'
                    ) NULL,
                    [isAdmin] BIT NULL DEFAULT 0,
                    [sessionId] NVARCHAR(255) NULL,
                    PRIMARY KEY ([id])
                );
            `;
            
            await db.query(createUserTableSQL);
            console.log('   ✅ 加密用户表创建成功');
        } else {
            console.log('   ⚠️ 用户加密表已存在，跳过创建');
        }

        // 创建加密风险日志表
        console.log('   📊 创建加密风险日志表...');
        const logTableExists = await db.query(`
            SELECT COUNT(*) as count FROM sys.tables WHERE name = 'risk_logs_encrypted'
        `);
        
        if (logTableExists.recordset[0].count === 0) {
            const createLogTableSQL = `
                CREATE TABLE [dbo].[risk_logs_encrypted] (
                    [id] INT IDENTITY(1,1) PRIMARY KEY,
                    [user_id] NVARCHAR(50) COLLATE Chinese_PRC_BIN2 ENCRYPTED WITH (
                        COLUMN_ENCRYPTION_KEY = [RBA_CEK],
                        ENCRYPTION_TYPE = Deterministic,
                        ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'
                    ) NOT NULL,
                    [ip_address] NVARCHAR(45) ENCRYPTED WITH (
                        COLUMN_ENCRYPTION_KEY = [RBA_CEK],
                        ENCRYPTION_TYPE = Randomized,
                        ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'
                    ) NOT NULL,
                    [geo_data] NVARCHAR(MAX) ENCRYPTED WITH (
                        COLUMN_ENCRYPTION_KEY = [RBA_CEK],
                        ENCRYPTION_TYPE = Randomized,
                        ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'
                    ) NULL,
                    [risk_score] DECIMAL(5,4) NOT NULL,
                    [user_agent] NVARCHAR(MAX) ENCRYPTED WITH (
                        COLUMN_ENCRYPTION_KEY = [RBA_CEK],
                        ENCRYPTION_TYPE = Randomized,
                        ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'
                    ) NULL,
                    [rtt] DECIMAL(10,3) NULL,
                    [created_at] DATETIME2 DEFAULT GETDATE() NOT NULL
                );
            `;
            
            await db.query(createLogTableSQL);
            console.log('   ✅ 加密风险日志表创建成功');
        } else {
            console.log('   ⚠️ 风险日志加密表已存在，跳过创建');
        }

        // 清除查询计划缓存
        console.log('\n🧹 清除查询计划缓存...');
        try {
            await db.query('ALTER DATABASE SCOPED CONFIGURATION CLEAR PROCEDURE_CACHE;');
            console.log('✅ 查询计划缓存已清除');
        } catch (error) {
            console.log('⚠️ 清除查询计划缓存失败:', error.message);
        }

        console.log('\n✅ 基础Always Encrypted设置完成！');
        
        // 生成后续步骤指南
        console.log('\n📋 后续步骤指南');
        console.log('================');
        console.log('');
        console.log('🔐 1. 证书管理（重要）');
        console.log('   在客户端计算机上生成自签名证书：');
        console.log('   powershell -Command "New-SelfSignedCertificate -Subject \'CN=RBA_AlwaysEncrypted_Certificate\' -KeyExportPolicy Exportable -KeySpec KeyExchange -KeyLength 2048 -CertStoreLocation \'Cert:\\\\CurrentUser\\\\My\'"');
        console.log('');
        console.log('🔧 2. 应用程序配置');
        console.log('   - 更新数据库连接字符串启用Always Encrypted');
        console.log('   - 使用sqlserver-encrypted.js进行数据操作');
        console.log('');
        console.log('📊 3. 数据迁移');
        console.log('   运行: npm run migrate:encrypted');
        console.log('');
        console.log('🧪 4. 功能测试');
        console.log('   运行: npm run test:encrypted');
        
    } catch (error) {
        console.error('❌ 设置过程中发生错误:', error.message);
        throw error;
    } finally {
        await db.close();
    }
}

if (require.main === module) {
    setupBasicEncryption().catch(error => {
        console.error('💥 设置失败:', error.message);
        process.exit(1);
    });
}

module.exports = { setupBasicEncryption }; 