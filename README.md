# 🔐 RBA 风险评估系统 - Always Encrypted 数据加密方案

## 📌 项目概述

**RBA (Risk-Based Authentication)** 风险评估系统，集成了 **SQL Server Always Encrypted** 数据库级加密功能，实现敏感数据的透明加密存储。

### 🏗️ 系统架构
- **后端**: Node.js + Express
- **数据库**: 阿里云RDS SQL Server 2019 (Always Encrypted)
- **风险评估**: Python + IP地理位置 + 用户行为分析
- **加密**: 列级透明加密，客户端证书管理

---

## ✅ 已完成功能

### 🔑 **第一阶段：Always Encrypted 基础设置** ✅
- [x] **环境检查**: `check-rds-capabilities.sql` - 验证RDS环境支持
- [x] **证书管理**: `create-certificate.ps1` - 生成客户端证书
- [x] **密钥管理**: 
  - 列主密钥 (CMK): `RBA_CMK`
  - 列加密密钥 (CEK): `RBA_CEK`
- [x] **加密表结构**:
  - `users_encrypted` - 用户数据加密表
  - `risk_logs_encrypted` - 风险日志加密表
- [x] **排序规则**: 修复确定性加密的 `Chinese_PRC_BIN2` 要求

### 📊 **核心风险评估引擎** ✅
- [x] **IP地理位置分析**: 基于GeoIP数据库
- [x] **用户行为分析**: 登录时间、频率模式
- [x] **设备指纹识别**: User-Agent分析
- [x] **网络延迟检测**: RTT测量
- [x] **风险评分算法**: 多维度综合评估

### 🔧 **数据库连接层** ✅
- [x] **基础连接**: `sqlserver-connection.js` - 标准SQL Server连接
- [x] **加密连接**: `sqlserver-encrypted.js` - Always Encrypted支持
- [x] **连接池管理**: 自动重连、超时处理

---

## 🚧 待完成任务

### 📦 **第二阶段：数据迁移** 🔄
- [ ] **JSON到SQL迁移**: `migrate-to-encrypted.js`
  - [ ] 用户数据迁移 (`users.json` → `users_encrypted`)
  - [ ] 历史数据清理和验证
  - [ ] 数据完整性检查

### 🧪 **第三阶段：功能测试** 🔄  
- [ ] **加密功能测试**: `test-always-encrypted.js`
  - [ ] 数据加密/解密验证
  - [ ] 查询性能测试
  - [ ] 并发访问测试
  - [ ] 错误处理测试

### 🔗 **第四阶段：应用集成** ⏳
- [ ] **API层改造**: 更新 `server.js` 使用加密连接
- [ ] **风险评估集成**: `core.py` 与加密数据库集成
- [ ] **中间件更新**: 身份验证和授权中间件
- [ ] **前端适配**: 处理加密数据的前端逻辑

### 🚀 **第五阶段：生产部署** ⏳
- [ ] **环境配置**: 生产环境Always Encrypted配置
- [ ] **证书部署**: 生产环境证书管理
- [ ] **性能优化**: 查询优化和缓存策略
- [ ] **监控告警**: 加密状态监控

---

## 📂 项目文件结构

```
RBA/
├── 📋 README.md                    # 项目主文档 (本文件)
├── 🔧 package.json                 # 项目依赖配置
├── 
├── 🌐 服务器核心
│   ├── server.js                   # Express服务器主文件
│   ├── core.py                     # Python风险评估引擎
│   └── users.json                  # 用户数据 (待迁移)
├── 
├── 💾 数据库层
│   ├── sqlserver-connection.js     # 标准数据库连接
│   ├── sqlserver-encrypted.js      # Always Encrypted连接
│   └── check-rds-capabilities.sql  # 环境检查SQL脚本
├── 
├── 🔐 Always Encrypted
│   ├── create-certificate.ps1      # 证书生成脚本
│   ├── rds-setup.js                # 加密环境设置
│   ├── migrate-to-encrypted.js     # 数据迁移工具
│   └── test-always-encrypted.js    # 加密功能测试
├── 
└── 🎯 风险评估引擎
    └── src/risk/
        ├── engine.js               # 风险评估核心算法
        └── config.js               # 风险评估配置
```

---

## 🚀 快速开始

### 1️⃣ **环境检查**
```bash
# 在SSMS中运行环境检查
check-rds-capabilities.sql
```

### 2️⃣ **生成证书**
```bash
npm run create:certificate
```

### 3️⃣ **设置Always Encrypted**
```bash
npm run setup:basic-encryption
```

### 4️⃣ **数据迁移** (下一步)
```bash
npm run migrate:encrypted
```

### 5️⃣ **功能测试** (下一步)
```bash
npm run test:encrypted
```

---

## 📊 加密方案详情

### 🔑 **密钥管理**
- **列主密钥 (CMK)**: `RBA_CMK`
  - 存储位置: `CurrentUser/My/RBA_AlwaysEncrypted_Certificate`
  - 证书指纹: `02019EA80F7C0E07CE764E146CABDE8FA6092949`
  - 算法: RSA 2048位

- **列加密密钥 (CEK)**: `RBA_CEK`
  - 基于CMK生成
  - 算法: `RSA_OAEP`

### 🗄️ **加密表结构**

#### `users_encrypted` - 用户数据表
| 列名 | 类型 | 加密类型 | 说明 |
|------|------|----------|------|
| `id` | NVARCHAR(50) | 无 | 主键 |
| `username` | NVARCHAR(50) | 确定性 | 支持等值查询 |
| `email` | NVARCHAR(255) | 随机化 | 最高安全性 |
| `password` | NVARCHAR(255) | 随机化 | 密码散列 |
| `loginHistory` | NVARCHAR(MAX) | 随机化 | JSON格式历史 |

#### `risk_logs_encrypted` - 风险日志表
| 列名 | 类型 | 加密类型 | 说明 |
|------|------|----------|------|
| `id` | INT IDENTITY | 无 | 自增主键 |
| `user_id` | NVARCHAR(50) | 确定性 | 关联用户 |
| `ip_address` | NVARCHAR(45) | 随机化 | IP地址 |
| `geo_data` | NVARCHAR(MAX) | 随机化 | 地理位置JSON |
| `user_agent` | NVARCHAR(MAX) | 随机化 | 设备信息 |
| `risk_score` | DECIMAL(5,4) | 无 | 风险评分 |

---

## ⚡ 性能考虑

### 🔍 **查询限制**
- **确定性加密**: 支持 `=` 查询，不支持 `LIKE`、范围查询
- **随机化加密**: 不支持任何查询条件，只能检索后解密
- **排序规则**: 确定性加密列必须使用 `*_BIN2` 排序规则

### 🚀 **优化建议**
- 敏感数据使用随机化加密
- 需要查询的字段使用确定性加密
- 非敏感字段保持明文以提高性能
- 合理使用索引和查询计划

---

## 🔒 安全注意事项

### 🎯 **证书管理**
- ⚠️ **关键**: 证书丢失将导致数据无法解密
- 🔄 **备份**: 定期备份证书到安全位置
- 🔐 **权限**: 严格控制证书访问权限
- 📅 **轮换**: 定期更新证书和密钥

### 🛡️ **访问控制**
- 只有具备正确证书的客户端才能解密数据
- 数据库管理员无法直接查看加密数据
- 应用程序需要配置Always Encrypted连接字符串

---

## 📞 技术支持

### 🔧 **常用命令**
```bash
# 环境检查
npm run check:rds

# 生成证书  
npm run create:certificate

# 设置加密
npm run setup:basic-encryption

# 数据迁移
npm run migrate:encrypted

# 功能测试
npm run test:encrypted
```

### 📋 **故障排除**
1. **证书问题**: 重新生成证书并更新CMK
2. **连接失败**: 检查数据库配置和网络连接
3. **查询错误**: 确认列的加密类型和排序规则
4. **性能问题**: 优化查询语句，避免全表扫描

---

## 📈 项目进度

```
进度: ████████████░░░░░░░░ 60%

✅ 已完成 (60%)
├── Always Encrypted基础设置
├── 证书和密钥管理  
├── 加密表结构创建
├── 风险评估引擎
└── 数据库连接层

🚧 进行中 (40%)
├── 数据迁移工具
├── 功能测试框架
├── 应用层集成
└── 生产环境部署
```

---

**最后更新**: 2025-06-07
**状态**: 第一阶段完成，准备开始数据迁移 