const fs = require('fs');
const path = require('path');
const EncryptedSQLServerConnection = require('./sqlserver-encrypted');

class DataMigrationService {
    constructor() {
        this.encryptedDB = new EncryptedSQLServerConnection();
        this.usersFile = path.join(__dirname, 'users.json');
    }

    /**
     * 执行完整的数据迁移
     */
    async migrateAllData() {
        try {
            console.log('🚀 开始数据迁移到Always Encrypted表...');
            
            // 连接数据库
            await this.encryptedDB.connect();
            
            // 迁移用户数据
            await this.migrateUsers();
            
            // 迁移风险日志（如果需要的话）
            // await this.migrateRiskLogs();
            
            console.log('✅ 数据迁移完成！');
        } catch (error) {
            console.error('❌ 数据迁移失败:', error.message);
            throw error;
        } finally {
            await this.encryptedDB.close();
        }
    }

    /**
     * 迁移用户数据从JSON文件到加密表
     */
    async migrateUsers() {
        try {
            console.log('📝 开始迁移用户数据...');
            
            // 读取现有用户数据
            if (!fs.existsSync(this.usersFile)) {
                console.log('⚠️ users.json文件不存在，跳过用户数据迁移');
                return;
            }

            const usersData = JSON.parse(fs.readFileSync(this.usersFile, 'utf8'));
            console.log(`📊 发现 ${usersData.length} 个用户记录`);

            let successCount = 0;
            let errorCount = 0;

            for (const user of usersData) {
                try {
                    // 检查用户是否已经存在于加密表中
                    const existingUser = await this.encryptedDB.findUserByUsername(user.username);
                    
                    if (existingUser) {
                        console.log(`⚠️ 用户 ${user.username} 已存在于加密表中，跳过`);
                        continue;
                    }

                    // 准备迁移数据
                    const migratedUser = {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        password: user.password,
                        createdAt: new Date(user.createdAt),
                        lastLogin: user.lastLogin ? new Date(user.lastLogin) : null,
                        loginHistory: user.loginHistory || [],
                        isAdmin: user.isAdmin || false,
                        sessionId: user.sessionId || null
                    };

                    // 插入到加密表
                    await this.encryptedDB.insertEncryptedUser(migratedUser);
                    console.log(`✅ 用户 ${user.username} 迁移成功`);
                    successCount++;

                } catch (userError) {
                    console.error(`❌ 迁移用户 ${user.username} 失败:`, userError.message);
                    errorCount++;
                }
            }

            console.log(`📈 用户数据迁移统计: 成功 ${successCount} 个，失败 ${errorCount} 个`);
            
        } catch (error) {
            console.error('❌ 用户数据迁移失败:', error.message);
            throw error;
        }
    }

    /**
     * 验证迁移结果
     */
    async validateMigration() {
        try {
            console.log('🔍 验证迁移结果...');
            
            await this.encryptedDB.connect();

            // 统计加密表中的用户数量
            const userCountResult = await this.encryptedDB.query(`
                SELECT COUNT(*) as user_count FROM [dbo].[users_encrypted]
            `);
            
            const encryptedUserCount = userCountResult.recordset[0].user_count;
            
            // 读取原始数据数量
            const originalUsers = JSON.parse(fs.readFileSync(this.usersFile, 'utf8'));
            const originalUserCount = originalUsers.length;

            console.log(`📊 验证结果:`);
            console.log(`   原始用户数量: ${originalUserCount}`);
            console.log(`   加密表用户数量: ${encryptedUserCount}`);
            
            if (encryptedUserCount === originalUserCount) {
                console.log('✅ 数据迁移验证通过！');
            } else {
                console.log('⚠️ 数据数量不匹配，请检查迁移过程');
            }

            // 测试加密数据的查询功能
            await this.testEncryptedQueries();

        } catch (error) {
            console.error('❌ 验证迁移结果失败:', error.message);
            throw error;
        } finally {
            await this.encryptedDB.close();
        }
    }

    /**
     * 测试加密数据的查询功能
     */
    async testEncryptedQueries() {
        try {
            console.log('🧪 测试加密查询功能...');

            // 测试用户查询
            const originalUsers = JSON.parse(fs.readFileSync(this.usersFile, 'utf8'));
            if (originalUsers.length > 0) {
                const testUsername = originalUsers[0].username;
                const foundUser = await this.encryptedDB.findUserByUsername(testUsername);
                
                if (foundUser && foundUser.username === testUsername) {
                    console.log('✅ 加密用户查询测试通过');
                } else {
                    console.log('❌ 加密用户查询测试失败');
                }
            }

        } catch (error) {
            console.error('❌ 测试加密查询失败:', error.message);
        }
    }

    /**
     * 创建数据备份
     */
    async createBackup() {
        try {
            console.log('💾 创建数据备份...');
            
            const backupDir = path.join(__dirname, 'backup');
            if (!fs.existsSync(backupDir)) {
                fs.mkdirSync(backupDir);
            }

            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const backupFile = path.join(backupDir, `users_backup_${timestamp}.json`);

            // 复制原始用户文件
            if (fs.existsSync(this.usersFile)) {
                fs.copyFileSync(this.usersFile, backupFile);
                console.log(`✅ 用户数据备份至: ${backupFile}`);
            }

        } catch (error) {
            console.error('❌ 创建备份失败:', error.message);
            throw error;
        }
    }

    /**
     * 清理旧数据（谨慎使用）
     */
    async cleanupOldData() {
        try {
            console.log('🧹 清理旧数据...');
            
            // 重命名原始用户文件而不是删除
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const oldFile = path.join(__dirname, `users_old_${timestamp}.json`);
            
            if (fs.existsSync(this.usersFile)) {
                fs.renameSync(this.usersFile, oldFile);
                console.log(`✅ 原始用户文件已重命名为: ${oldFile}`);
            }

        } catch (error) {
            console.error('❌ 清理旧数据失败:', error.message);
            throw error;
        }
    }
}

// 主执行函数
async function main() {
    const migrationService = new DataMigrationService();
    
    try {
        console.log('🎯 SQL Server Always Encrypted 数据迁移工具');
        console.log('================================================');
        
        // 创建备份
        await migrationService.createBackup();
        
        // 执行迁移
        await migrationService.migrateAllData();
        
        // 验证迁移结果
        await migrationService.validateMigration();
        
        console.log('');
        console.log('🎉 数据迁移流程完成！');
        console.log('');
        console.log('⚠️ 后续步骤:');
        console.log('1. 请验证应用程序能正常使用加密数据');
        console.log('2. 测试完成后可以考虑清理旧数据');
        console.log('3. 请确保备份证书和密钥');

    } catch (error) {
        console.error('💥 迁移过程中发生错误:', error.message);
        process.exit(1);
    }
}

// 如果直接运行此脚本
if (require.main === module) {
    main();
}

module.exports = DataMigrationService; 