-- 阿里云RDS SQL Server Always Encrypted能力检查
-- 第一阶段：环境检查脚本
-- 请在SSMS或其他SQL客户端中运行此脚本

PRINT '🎯 阿里云RDS SQL Server Always Encrypted环境检查';
PRINT '===================================================';
PRINT '';

-- 1. 检查当前用户权限
PRINT '🔑 检查用户权限...';
SELECT 
    '当前用户' = USER_NAME(),
    '系统用户' = SYSTEM_USER,
    '系统管理员' = CASE WHEN IS_SRVROLEMEMBER('sysadmin') = 1 THEN '✅ 是' ELSE '❌ 否' END,
    '数据库创建者' = CASE WHEN IS_SRVROLEMEMBER('dbcreator') = 1 THEN '✅ 是' ELSE '❌ 否' END,
    '安全管理员' = CASE WHEN IS_SRVROLEMEMBER('securityadmin') = 1 THEN '✅ 是' ELSE '❌ 否' END,
    '数据库所有者' = CASE WHEN IS_MEMBER('db_owner') = 1 THEN '✅ 是' ELSE '❌ 否' END;

-- 2. 检查SQL Server版本和Always Encrypted支持
PRINT '';
PRINT '📊 检查SQL Server版本...';
SELECT 
    '产品版本' = SERVERPROPERTY('ProductVersion'),
    '版本级别' = SERVERPROPERTY('ProductLevel'),
    '版本类型' = SERVERPROPERTY('Edition'),
    'Always Encrypted支持' = CASE 
        WHEN CAST(SUBSTRING(CAST(SERVERPROPERTY('ProductVersion') AS VARCHAR), 1, 2) AS INT) >= 13 
        THEN '✅ 支持 (SQL 2016+)' 
        ELSE '❌ 不支持' 
    END,
    'Enclaves理论支持' = CASE 
        WHEN CAST(SUBSTRING(CAST(SERVERPROPERTY('ProductVersion') AS VARCHAR), 1, 2) AS INT) >= 15 
        THEN '✅ 支持 (SQL 2019+)' 
        ELSE '❌ 不支持' 
    END;

-- 3. 检查Always Encrypted相关系统视图
PRINT '';
PRINT '🔐 检查Always Encrypted系统视图...';
SELECT 
    '列主密钥视图' = CASE WHEN OBJECT_ID('sys.column_master_keys') IS NOT NULL THEN '✅ 可用' ELSE '❌ 不可用' END,
    '列加密密钥视图' = CASE WHEN OBJECT_ID('sys.column_encryption_keys') IS NOT NULL THEN '✅ 可用' ELSE '❌ 不可用' END,
    '密钥值视图' = CASE WHEN OBJECT_ID('sys.column_encryption_key_values') IS NOT NULL THEN '✅ 可用' ELSE '❌ 不可用' END;

-- 4. 检查Enclave相关配置（在RDS中可能不可用）
PRINT '';
PRINT '🛡️ 检查Enclave配置...';
IF EXISTS (SELECT 1 FROM sys.configurations WHERE name = 'column encryption enclave type')
BEGIN
    SELECT 
        '配置名称' = name,
        '当前值' = value,
        '使用中的值' = value_in_use,
        '状态' = CASE 
            WHEN value_in_use = 1 THEN '✅ Enclave已启用'
            ELSE '⚠️ Enclave未启用'
        END
    FROM sys.configurations 
    WHERE name = 'column encryption enclave type';
END
ELSE
BEGIN
    SELECT '⚠️ Enclave配置不可用（阿里云RDS正常现象）' as 结果;
END

-- 5. 检查现有的Always Encrypted密钥
PRINT '';
PRINT '🔑 检查现有加密密钥...';
SELECT 
    '列主密钥数量' = (SELECT COUNT(*) FROM sys.column_master_keys),
    '列加密密钥数量' = (SELECT COUNT(*) FROM sys.column_encryption_keys);

-- 如果有现有密钥，显示详细信息
IF EXISTS (SELECT 1 FROM sys.column_master_keys)
BEGIN
    PRINT '';
    PRINT '📋 现有列主密钥详情:';
    SELECT 
        '密钥名称' = name,
        '密钥存储提供程序' = key_store_provider_name,
        '密钥路径' = key_path,
        '支持Enclave计算' = CASE WHEN allow_enclave_computations = 1 THEN '✅ 是' ELSE '❌ 否' END
    FROM sys.column_master_keys;
END

IF EXISTS (SELECT 1 FROM sys.column_encryption_keys)
BEGIN
    PRINT '';
    PRINT '📋 现有列加密密钥详情:';
    SELECT 
        '密钥名称' = cek.name,
        '关联的列主密钥' = cmk.name
    FROM sys.column_encryption_keys cek
    LEFT JOIN sys.column_encryption_key_values cekv ON cek.column_encryption_key_id = cekv.column_encryption_key_id
    LEFT JOIN sys.column_master_keys cmk ON cekv.column_master_key_id = cmk.column_master_key_id;
END

-- 6. 检查数据库权限
PRINT '';
PRINT '📊 检查数据库级别权限...';
SELECT 
    '控制数据库权限' = CASE WHEN HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CONTROL') = 1 THEN '✅ 有' ELSE '❌ 无' END,
    '修改数据库权限' = CASE WHEN HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'ALTER') = 1 THEN '✅ 有' ELSE '❌ 无' END,
    '创建表权限' = CASE WHEN HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CREATE TABLE') = 1 THEN '✅ 有' ELSE '❌ 无' END;

-- 7. 生成实施建议
PRINT '';
PRINT '💡 实施建议：';
PRINT '==========';

-- 检查是否满足基本条件
DECLARE @can_implement BIT = 0;
DECLARE @version_ok BIT = 0;
DECLARE @permissions_ok BIT = 0;

-- 检查版本
IF CAST(SUBSTRING(CAST(SERVERPROPERTY('ProductVersion') AS VARCHAR), 1, 2) AS INT) >= 13
    SET @version_ok = 1;

-- 检查权限
IF (HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CONTROL') = 1 OR IS_MEMBER('db_owner') = 1)
    SET @permissions_ok = 1;

SET @can_implement = @version_ok & @permissions_ok;

IF @can_implement = 1
BEGIN
    PRINT '✅ 环境检查通过，可以实施Always Encrypted';
    PRINT '';
    PRINT '🎯 推荐方案：基础Always Encrypted（适合阿里云RDS）';
    PRINT '   - 支持列级数据加密';
    PRINT '   - 确定性加密支持等值查询';
    PRINT '   - 随机化加密提供最高安全性';
    PRINT '';
    PRINT '🚀 下一步操作：';
    PRINT '1. 生成或获取客户端证书';
    PRINT '2. 创建列主密钥 (CMK)';
    PRINT '3. 创建列加密密钥 (CEK)';
    PRINT '4. 创建加密表结构';
    PRINT '5. 配置应用程序连接';
    PRINT '6. 迁移现有数据';
END
ELSE
BEGIN
    IF @version_ok = 0
        PRINT '❌ SQL Server版本不支持Always Encrypted，需要2016或更高版本';
    
    IF @permissions_ok = 0
        PRINT '❌ 权限不足，需要数据库控制权限或db_owner角色';
    
    PRINT '';
    PRINT '请解决上述问题后重新检查';
END

PRINT '';
PRINT '🎉 第一阶段环境检查完成！'; 