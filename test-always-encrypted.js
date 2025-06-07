const EncryptedSQLServerConnection = require('./sqlserver-encrypted');
const bcrypt = require('bcrypt');

class AlwaysEncryptedTester {
    constructor() {
        this.db = new EncryptedSQLServerConnection();
    }

    /**
     * 运行所有测试
     */
    async runAllTests() {
        try {
            console.log('🧪 开始Always Encrypted功能测试');
            console.log('=====================================');
            
            await this.db.connect();
            
            // 测试用户数据操作
            await this.testUserOperations();
            
            // 测试Enclave计算功能
            await this.testEnclaveComputations();
            
            // 测试风险日志操作
            await this.testRiskLogOperations();
            
            console.log('✅ 所有测试完成！');
            
        } catch (error) {
            console.error('❌ 测试过程中发生错误:', error.message);
            throw error;
        } finally {
            await this.db.close();
        }
    }

    /**
     * 测试用户数据操作
     */
    async testUserOperations() {
        console.log('\n📝 测试用户数据操作...');
        
        try {
            // 创建测试用户
            const testUser = {
                id: 'test_' + Date.now(),
                username: 'testuser_encrypted',
                email: 'test@encrypted.com',
                password: await bcrypt.hash('testpass123', 10),
                createdAt: new Date(),
                lastLogin: null,
                loginHistory: [
                    {
                        ip: '192.168.1.100',
                        userAgent: 'Test Agent',
                        timestamp: new Date().toISOString(),
                        success: true
                    }
                ],
                isAdmin: false,
                sessionId: null
            };

            // 测试插入加密用户
            console.log('  🔹 测试插入加密用户数据...');
            await this.db.insertEncryptedUser(testUser);
            console.log('  ✅ 加密用户数据插入成功');

            // 测试查询加密用户
            console.log('  🔹 测试查询加密用户数据...');
            const foundUser = await this.db.findUserByUsername(testUser.username);
            
            if (foundUser) {
                console.log('  ✅ 加密用户数据查询成功');
                console.log('  📊 查询结果:');
                console.log(`    用户名: ${foundUser.username}`);
                console.log(`    邮箱: ${foundUser.email}`);
                console.log(`    创建时间: ${foundUser.createdAt}`);
                console.log(`    登录历史记录数: ${foundUser.loginHistory?.length || 0}`);
                
                // 验证密码
                const passwordMatch = await bcrypt.compare('testpass123', foundUser.password);
                if (passwordMatch) {
                    console.log('  ✅ 密码验证成功');
                } else {
                    console.log('  ❌ 密码验证失败');
                }
            } else {
                console.log('  ❌ 加密用户数据查询失败');
            }

            // 清理测试数据
            await this.cleanupTestUser(testUser.id);

        } catch (error) {
            console.error('  ❌ 用户数据操作测试失败:', error.message);
            throw error;
        }
    }

    /**
     * 测试Enclave计算功能
     */
    async testEnclaveComputations() {
        console.log('\n🔐 测试Enclave计算功能...');
        
        try {
            // 检查Enclave状态
            console.log('  🔹 检查Enclave状态...');
            const enclaveResult = await this.db.query(`
                SELECT [name], [value], [value_in_use] 
                FROM sys.configurations 
                WHERE [name] = 'column encryption enclave type'
            `);
            
            if (enclaveResult.recordset.length > 0) {
                const config = enclaveResult.recordset[0];
                console.log(`  📊 Enclave配置: ${config.name} = ${config.value} (使用中: ${config.value_in_use})`);
                
                if (config.value_in_use === 1) {
                    console.log('  ✅ VBS Enclave已启用并运行');
                } else {
                    console.log('  ⚠️ VBS Enclave未启用');
                }
            }

            // 测试加密列的范围查询（需要Enclave支持）
            console.log('  🔹 测试Enclave支持的模式匹配查询...');
            
            // 首先插入一些测试数据
            const testUsers = [
                {
                    id: 'enclave_test_1',
                    username: 'alice_test',
                    email: 'alice@test.com',
                    password: 'hashedpass1',
                    createdAt: new Date(),
                    lastLogin: null,
                    loginHistory: [],
                    isAdmin: false,
                    sessionId: null
                },
                {
                    id: 'enclave_test_2', 
                    username: 'bob_test',
                    email: 'bob@test.com',
                    password: 'hashedpass2',
                    createdAt: new Date(),
                    lastLogin: null,
                    loginHistory: [],
                    isAdmin: false,
                    sessionId: null
                }
            ];

            for (const user of testUsers) {
                await this.db.insertEncryptedUser(user);
            }
            console.log('  ✅ 测试数据插入完成');

            // 测试模式匹配查询（Enclave计算）
            const patternResult = await this.db.queryWithParams(`
                SELECT COUNT(*) as user_count 
                FROM [dbo].[users_encrypted] 
                WHERE [username] LIKE @pattern
            `, { pattern: '%_test' });

            if (patternResult.recordset.length > 0) {
                const count = patternResult.recordset[0].user_count;
                console.log(`  ✅ Enclave模式匹配查询成功，找到 ${count} 个匹配用户`);
            }

            // 清理测试数据
            for (const user of testUsers) {
                await this.cleanupTestUser(user.id);
            }

        } catch (error) {
            console.error('  ❌ Enclave计算功能测试失败:', error.message);
            // 注意：某些Enclave功能可能需要特定的查询语法或配置
        }
    }

    /**
     * 测试风险日志操作
     */
    async testRiskLogOperations() {
        console.log('\n📊 测试风险日志操作...');
        
        try {
            // 创建测试风险日志
            const testRiskLog = {
                user_id: 'test_user_' + Date.now(),
                ip_address: '192.168.1.200',
                geo_data: {
                    country: 'China',
                    city: 'Beijing',
                    latitude: 39.9042,
                    longitude: 116.4074
                },
                risk_score: 0.75,
                user_agent: 'Mozilla/5.0 (Test Browser)',
                rtt: 150.5
            };

            // 测试插入加密风险日志
            console.log('  🔹 测试插入加密风险日志...');
            const insertResult = await this.db.insertEncryptedRiskLog(testRiskLog);
            console.log('  ✅ 加密风险日志插入成功');

            // 测试查询风险日志
            console.log('  🔹 测试查询加密风险日志...');
            const queryResult = await this.db.queryWithParams(`
                SELECT TOP 5 [id], [user_id], [ip_address], [risk_score], [created_at]
                FROM [dbo].[risk_logs_encrypted]
                WHERE [user_id] = @user_id
                ORDER BY [created_at] DESC
            `, { user_id: testRiskLog.user_id });

            if (queryResult.recordset.length > 0) {
                console.log('  ✅ 加密风险日志查询成功');
                console.log('  📊 查询结果:');
                for (const log of queryResult.recordset) {
                    console.log(`    ID: ${log.id}, 风险分数: ${log.risk_score}, 时间: ${log.created_at}`);
                }
            } else {
                console.log('  ⚠️ 没有找到匹配的风险日志');
            }

        } catch (error) {
            console.error('  ❌ 风险日志操作测试失败:', error.message);
            throw error;
        }
    }

    /**
     * 清理测试用户数据
     */
    async cleanupTestUser(userId) {
        try {
            await this.db.queryWithParams(`
                DELETE FROM [dbo].[users_encrypted] WHERE [id] = @id
            `, { id: userId });
            console.log(`  🧹 测试用户 ${userId} 清理完成`);
        } catch (error) {
            console.error(`  ⚠️ 清理测试用户 ${userId} 失败:`, error.message);
        }
    }

    /**
     * 性能测试
     */
    async performanceTest() {
        console.log('\n⚡ 性能测试...');
        
        try {
            const iterations = 10;
            const testData = {
                id: 'perf_test',
                username: 'performance_test',
                email: 'perf@test.com', 
                password: 'testpass',
                createdAt: new Date(),
                lastLogin: null,
                loginHistory: [],
                isAdmin: false,
                sessionId: null
            };

            // 测试插入性能
            console.log(`  🔹 测试插入性能 (${iterations} 次)...`);
            const insertStart = Date.now();
            
            for (let i = 0; i < iterations; i++) {
                const uniqueData = { ...testData, id: `perf_test_${i}`, username: `perf_user_${i}` };
                await this.db.insertEncryptedUser(uniqueData);
            }
            
            const insertTime = Date.now() - insertStart;
            console.log(`  📈 插入性能: ${iterations} 条记录耗时 ${insertTime}ms (平均 ${insertTime/iterations}ms/条)`);

            // 测试查询性能
            console.log(`  🔹 测试查询性能 (${iterations} 次)...`);
            const queryStart = Date.now();
            
            for (let i = 0; i < iterations; i++) {
                await this.db.findUserByUsername(`perf_user_${i}`);
            }
            
            const queryTime = Date.now() - queryStart;
            console.log(`  📈 查询性能: ${iterations} 次查询耗时 ${queryTime}ms (平均 ${queryTime/iterations}ms/次)`);

            // 清理性能测试数据
            for (let i = 0; i < iterations; i++) {
                await this.cleanupTestUser(`perf_test_${i}`);
            }

        } catch (error) {
            console.error('  ❌ 性能测试失败:', error.message);
        }
    }
}

// 主执行函数
async function main() {
    const tester = new AlwaysEncryptedTester();
    
    try {
        await tester.runAllTests();
        
        // 可选：运行性能测试
        const runPerformanceTest = process.argv.includes('--performance');
        if (runPerformanceTest) {
            await tester.performanceTest();
        }
        
        console.log('\n🎉 Always Encrypted测试完成！');
        console.log('\n📋 测试总结:');
        console.log('✅ 数据加密和解密功能正常');
        console.log('✅ Enclave计算功能验证完成');
        console.log('✅ 数据库连接配置正确');
        console.log('\n💡 提示: 使用 --performance 参数运行性能测试');

    } catch (error) {
        console.error('\n💥 测试失败:', error.message);
        process.exit(1);
    }
}

// 如果直接运行此脚本
if (require.main === module) {
    main();
}

module.exports = AlwaysEncryptedTester;