// File: middlewares/history-store.js
const mysql = require('mysql2/promise');
const config = require('../src/risk/config.js');

class HistoryStore {

  
  constructor() {
    this.users = {}; // 显式初始化 ✅
    this.pool = mysql.createPool(config.database);
    // 初始化连接池（复用config中的数据库配置）
    // this.pool = mysql.createPool({
    //   ...config.database,
    //   namedPlaceholders: true, // 启用命名占位符
    //   timezone: '+00:00'      // 统一使用UTC时间
    // });
    this.cache = {
      users: {},       // 用户历史缓存
      globalStats: {   // 全局统计缓存
        totalLoginCount: 0,
        featureStats: {},
        totalStats: {}
      },
      lastUpdated: 0   // 最后更新时间戳
    };
    
  }
  async getGlobalFeatureStats() {
    if (Date.now() - this.cache.lastUpdated < 60000) { // 缓存1分钟
      return this.cache.globalStats.featureStats;
    }
    const stats = await this._getGlobalFeatureStats(); // 原始方法
    this.cache.globalStats.featureStats = stats;
    this.cache.lastUpdated = Date.now();
    return stats;
  }

  /**
   * 记录风险分析结果
   * @param {Object} params - 参数对象
   * @param {string} params.user_id - 用户ID（对应数据库字段）
   * @param {string} params.ip_address - IP地址
   * @param {Object} params.geo_data - 地理数据对象
   * @param {number} params.risk_score - 风险评分
   * @returns {Promise<number>} 插入的记录ID
   */
  async logRiskEvent({ user_id, ip_address, geo_data, risk_score, user_agent }) {
       // 参数检查增强版
       const missingParams = [];
       const params = [
           { name: 'user_id', value: user_id },
           { name: 'ip_address', value: ip_address },
           { name: 'geo_data', value: geo_data },
           { name: 'risk_score', value: risk_score }
       ];
   
       // 检查每个参数
       params.forEach(param => {
           if (!param.value) {
               missingParams.push(param.name);
               console.error(`[风险日志错误] 缺失参数检测: ${param.name}`, {
                   eventType: "PARAM_MISSING",
                   param: param.name,
                   timestamp: new Date().toISOString()
               });
           }
       });
   
       // 如果有缺失参数则报错
       if (missingParams.length > 0) {
           throw new Error(`缺少必需的参数: ${missingParams.join(', ')}`);
       }
  
    const connection = await this.pool.getConnection();
    try {
      const [result] = await connection.execute(
        `INSERT INTO risk_logs 
        (user_id, ip_address, geo_data, risk_score, user_agent)
        VALUES (?, ?, ?, ?, ?)`,
        [user_id, ip_address, geo_data, risk_score, user_agent]
    );
      return result.insertId;
    } catch (error) {
      this.handleDBError(error, '风险日志记录失败');
      throw error; // 确保错误被正确传播
    } finally {
      connection.release();
    }
  }

  /**
   * 获取用户风险历史（精确匹配用户ID和时间范围）
   * @param {string} user_id - 用户ID
   * @param {Object} [options] - 查询选项
   * @param {number} [options.hours=24] - 查询时间范围（小时）
   * @param {number} [options.limit=50] - 最大返回数量
   * @returns {Promise<Array>} 风险日志数组
   */
  async getRiskHistory(user_id, { hours = 24, limit = 50 } = {}) {
    const connection = await this.pool.getConnection();
    try {
      const [rows] = await connection.execute(
        `SELECT 
          id,
          ip_address AS ip,
          geo_data AS geo,
          risk_score AS score,
          created_at AS timestamp
        FROM risk_logs
        WHERE user_id = :user_id
          AND created_at >= NOW() - INTERVAL :hours HOUR
        ORDER BY created_at DESC
        LIMIT :limit`,
        { user_id, hours, limit }
      );

      return rows.map(row => ({
        ...row,
        geo: JSON.parse(row.geo),
        timestamp: new Date(row.timestamp).toISOString()
      }));
    } catch (error) {
      this.handleDBError(error, '风险历史查询失败');
    } finally {
      connection.release();
    }
  }

  /**
   * 错误处理统一方法
   * @param {Error} error - 原始错误对象
   * @param {string} message - 自定义错误信息
   */
  handleDBError(error, message) {
    console.error(`[HistoryStore] ${message}:`, {
      code: error.code,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage,
      stack: error.stack
    });
    throw new Error(`${message}（错误码：${error.code}）`);
  }

  /**
   * 关闭连接池（用于优雅退出）
   */
  async close() {
    await this.pool.end();
    console.log('[HistoryStore] 数据库连接池已关闭');
  }

   /**
   * 获取全局登录总次数
   * @returns {Promise<number>}
   */
   async getTotalLoginCount() {
    const connection = await this.pool.getConnection();
    try {
      const [rows] = await connection.execute(
        'SELECT COUNT(*) AS total FROM risk_logs'
      );
      return rows[0].total || 0;
    } catch (error) {
      this.handleDBError(error, '全局登录次数查询失败');
    } finally {
      connection.release();
    }
  }

  /**
   * 获取全局特征统计
   * @returns {Promise<Object>}
   */
  async getGlobalFeatureStats() {
    const connection = await this.pool.getConnection();
    try {
      // 获取IP分布
      const [ipStats] = await connection.execute(
        `SELECT 
          ip_address AS feature,
          COUNT(*) AS count 
        FROM risk_logs 
        GROUP BY ip_address`
      );

      // 获取UA分布（需实际存储UA字段）
      const [uaStats] = await connection.execute(
        `SELECT 
          user_agent AS feature,
          COUNT(*) AS count 
        FROM risk_logs 
        GROUP BY user_agent`
      );

      return {
        ip: ipStats.reduce((acc, row) => {
          acc[row.feature] = row.count;
          return acc;
        }, {}),
        ua: uaStats.reduce((acc, row) => {
          acc[row.feature] = row.count;
          return acc;
        }, {}),
        rtt: {} // 根据实际需求实现
      };
    } catch (error) {
      this.handleDBError(error, '全局特征统计失败');
    } finally {
      connection.release();
    }
  }

  /**
   * 获取全局总计数
   * @returns {Promise<Object>}
   */
  async getGlobalTotalStats() {
    const connection = await this.pool.getConnection();
    try {
      const [total] = await connection.execute(
        `SELECT 
          COUNT(DISTINCT ip_address) AS ip,
          COUNT(DISTINCT user_agent) AS ua
        FROM risk_logs`
      );
      return {
        ip: total[0].ip,
        ua: total[0].ua,
        rtt: 0 // 根据实际需求实现
      };
    } catch (error) {
      this.handleDBError(error, '全局总计数查询失败');
    } finally {
      connection.release();
    }
  }
   /**
   * 初始化用户历史
   * @param {string} userId 
   * @returns {Promise<void>}
   */
   async initializeUserHistory(userId) {
    if (!userId) return;
    
    // 如果已经在缓存中，直接返回
    if (this.users[userId]) {
      console.log(`[HistoryStore] 用户历史已在缓存中: ${userId}`);
      return;
    }
    
    console.log(`[HistoryStore] 尝试从数据库加载用户历史: ${userId}`);
    const connection = await this.pool.getConnection();
    try {
      // 分两次查询：先获取登录次数，再获取IP统计
      const [loginCountResult] = await connection.execute(
        `SELECT COUNT(*) AS loginCount 
        FROM risk_logs 
        WHERE user_id = ?`,
        [userId]
      );
      
      console.log(`[HistoryStore] 用户 ${userId} 登录次数查询结果:`, loginCountResult[0]);
  
      const [ipStatsResult] = await connection.execute(
        `SELECT 
          ip_address AS ip,
          COUNT(*) AS count
        FROM risk_logs 
        WHERE user_id = ?
        GROUP BY ip_address`,
        [userId]
      );
      
      console.log(`[HistoryStore] 用户 ${userId} IP统计查询结果:`, ipStatsResult.length);
  
      // 转换为需要的结构
      const ipStats = ipStatsResult.reduce((acc, row) => {
        acc[row.ip] = row.count;
        return acc;
      }, {});
  
      this.users[userId] = {
        loginCount: loginCountResult[0].loginCount,
        features: { ip: ipStats },
        total: { ip: ipStatsResult.length }
      };
      
      console.log(`[HistoryStore] 用户历史加载成功: ${userId}`, this.users[userId]);
      return this.users[userId];
    } catch (error) {
      console.error(`[HistoryStore] 用户历史初始化失败: ${userId}`, error);
      return null;
    } finally {
      connection.release();
    }
  }
}

// 创建单例实例（供中间件使用）
const historyStoreInstance = new HistoryStore(); // 确保这行存在且变量名一致

// 修改中间件挂载方式
module.exports = {
  instance: historyStoreInstance, // 这里引用的变量必须与上面声明的一致
  middleware: (req, res, next) => {
    req.historyStore = historyStoreInstance;
    if (req.path === '/login' && req.method === 'POST') {
      historyStoreInstance.initializeUserHistory(req.user?.id)
        .catch(err => console.error('用户历史初始化失败:', err));
    }
    next();
  }
};