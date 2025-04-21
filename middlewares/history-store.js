// File: middlewares/history-store.js
const mysql = require('mysql2/promise');
const config = require('../src/risk/config.js');

class HistoryStore {

  constructor() {
    this.users = {}; // 显式初始化 ✅
    this.pool = mysql.createPool(config.database);
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

  // 新增：获取总登录次数方法
  async getTotalLoginCount() {
    try {
      // 首先尝试从缓存获取
      if (Date.now() - this.cache.lastUpdated < 60000) { // 缓存1分钟
        return this.cache.globalStats.totalLoginCount;
      }

      // 缓存过期，从数据库获取
      const connection = await this.pool.getConnection();
      try {
        const [rows] = await connection.execute('SELECT COUNT(*) as total FROM risk_logs');
        const count = rows[0]?.total || 0;
        
        // 更新缓存
        this.cache.globalStats.totalLoginCount = count;
        this.cache.lastUpdated = Date.now();
        
        return count;
      } finally {
        connection.release();
      }
    } catch (error) {
      console.error('获取总登录次数失败:', error);
      // 出错时返回缓存值或默认值
      return this.cache.globalStats.totalLoginCount || 1;
    }
  }

  // 新增：获取全局特征统计总数
  async getGlobalTotalStats() {
    try {
      if (Date.now() - this.cache.lastUpdated < 60000) { // 缓存1分钟
        return this.cache.globalStats.totalStats;
      }

      const connection = await this.pool.getConnection();
      try {
        // 查询每种特征类型的总计数
        const [rows] = await connection.execute(`
          SELECT feature_type, SUM(count) as total
          FROM feature_stats 
          WHERE user_id IS NULL
          GROUP BY feature_type
        `);

        // 处理结果为所需格式
        const totalStats = {};
        rows.forEach(row => {
          totalStats[row.feature_type] = row.total;
        });

        // 更新缓存
        this.cache.globalStats.totalStats = totalStats;
        this.cache.lastUpdated = Date.now();
        
        return totalStats;
      } finally {
        connection.release();
      }
    } catch (error) {
      console.error('获取全局特征统计总数失败:', error);
      return this.cache.globalStats.totalStats || {};
    }
  }

  async getGlobalFeatureStats() {
    if (Date.now() - this.cache.lastUpdated < 60000) { // 缓存1分钟
      return this.cache.globalStats.featureStats;
    }
    const stats = await this._getGlobalFeatureStats(); // 调用实际执行查询的方法
    this.cache.globalStats.featureStats = stats;
    this.cache.lastUpdated = Date.now();
    return stats;
  }

  // 实现缺失的 _getGlobalFeatureStats 方法
  async _getGlobalFeatureStats() {
    try {
      const connection = await this.pool.getConnection();
      try {
        // 查询所有全局特征统计（不包含用户特定统计）
        const [rows] = await connection.execute(`
          SELECT feature_type, feature_value, count
          FROM feature_stats 
          WHERE user_id IS NULL
        `);

        // 将结果组织为所需格式
        const featureStats = {};
        rows.forEach(row => {
          if (!featureStats[row.feature_type]) {
            featureStats[row.feature_type] = {};
          }
          featureStats[row.feature_type][row.feature_value] = row.count;
        });

        return featureStats;
      } finally {
        connection.release();
      }
    } catch (error) {
      console.error('获取全局特征统计失败:', error);
      return {};
    }
  }

  // 新增：初始化用户历史记录的方法
  async initializeUserHistory(userId, forceRefresh = false) {
    try {
      // 如果已在内存中且不强制刷新，则直接返回
      if (this.users[userId] && !forceRefresh) {
        return this.users[userId];
      }

      const connection = await this.pool.getConnection();
      try {
        // 获取用户登录次数
        const [loginCountRows] = await connection.execute(
          'SELECT COUNT(*) as count FROM risk_logs WHERE user_id = ?', 
          [userId]
        );
        const loginCount = loginCountRows[0]?.count || 0;

        // 获取用户特征统计
        const [featureRows] = await connection.execute(`
          SELECT feature_type, feature_value, count
          FROM feature_stats 
          WHERE user_id = ?
        `, [userId]);

        // 组织数据结构
        const features = {};
        const total = {};
        
        featureRows.forEach(row => {
          if (!features[row.feature_type]) {
            features[row.feature_type] = {};
            total[row.feature_type] = 0;
          }
          features[row.feature_type][row.feature_value] = row.count;
          total[row.feature_type] += row.count;
        });

        // 确保所有特征都被初始化
        ['ip', 'ua', 'bv', 'osv', 'df', 'asn', 'cc', 'rtt'].forEach(featureType => {
          if (!features[featureType]) features[featureType] = {};
          if (!total[featureType]) total[featureType] = 0;
        });

        // 创建并存储用户历史
        const userHistory = { 
          loginCount, 
          features, 
          total 
        };
        
        this.users[userId] = userHistory;
        return userHistory;
      } finally {
        connection.release();
      }
    } catch (error) {
      console.error(`初始化用户历史记录失败 (用户ID: ${userId}):`, error);
      return null;
    }
  }

  /**
   * 记录风险分析结果
   * @param {Object} params - 参数对象
   * @param {string} params.user_id - 用户ID（对应数据库字段）
   * @param {string} params.ip_address - IP地址
   * @param {Object} params.geo_data - 地理数据对象
   * @param {number} params.risk_score - 风险评分
   * @param {string} params.user_agent - 用户代理
   * @param {number} params.rtt - RTT 值
   * @returns {Promise<number>} 插入的记录ID
   */
  async logRiskEvent({ user_id, ip_address, geo_data, risk_score, user_agent, rtt }) {
    const missingParams = [];
    const params = [
      { name: 'user_id', value: user_id },
      { name: 'ip_address', value: ip_address },
      { name: 'geo_data', value: geo_data },
      { name: 'risk_score', value: risk_score },
      { name: 'rtt', value: rtt }
    ];

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

    if (missingParams.length > 0) {
      throw new Error(`缺少必需的参数: ${missingParams.join(', ')}`);
    }

    const connection = await this.pool.getConnection();
    try {
      // 1. 插入风险日志
      const [result] = await connection.execute(
        `INSERT INTO risk_logs 
        (user_id, ip_address, geo_data, risk_score, user_agent, rtt)
        VALUES (?, ?, ?, ?, ?, ?)`,
        [user_id, ip_address, JSON.stringify(geo_data), risk_score, user_agent, rtt]
      );

      // 2. 更新内存缓存
      this._updateInMemoryCache(user_id, { ip_address, geo_data, user_agent, rtt });

      // 3. 新增：更新特征统计表
      await this._updateFeatureStats(user_id, { ip_address, geo_data, user_agent, rtt });

      // 4. 新增：更新用户活动摘要表
      await this._updateUserActivitySummary(user_id, { ip_address, geo_data });

      return result.insertId;
    } catch (error) {
      this.handleDBError(error, '风险日志记录失败');
      throw error; // 确保错误被正确传播
    } finally {
      connection.release();
    }
  }

  /**
   * 更新特征统计表
   * @param {string} userId - 用户ID
   * @param {Object} features - 特征对象
   * @private
   */
  async _updateFeatureStats(userId, features) {
    try {
      const connection = await this.pool.getConnection();
      try {
        const featuresToUpdate = [];

        // 1. 处理IP特征
        if (features.ip_address) {
          featuresToUpdate.push({
            type: 'ip',
            value: features.ip_address,
            userId
          });
        }

        // 2. 处理User-Agent相关特征
        if (features.user_agent) {
          const UAParser = require('ua-parser-js');
          const parser = new UAParser(features.user_agent);
          const browser = parser.getBrowser();
          const os = parser.getOS();
          const device = parser.getDevice();

          featuresToUpdate.push({
            type: 'ua',
            value: browser.name || 'Unknown',
            userId
          });

          featuresToUpdate.push({
            type: 'bv',
            value: this._parseVersion(browser.version) || 'Unknown',
            userId
          });

          featuresToUpdate.push({
            type: 'osv',
            value: os.version || 'Unknown',
            userId
          });

          featuresToUpdate.push({
            type: 'df',
            value: device.model ? device.model : 'desktop',
            userId
          });
        }

        // 3. 处理地理位置特征
        if (features.geo_data) {
          featuresToUpdate.push({
            type: 'asn',
            value: features.geo_data.asn || 'Unknown',
            userId
          });

          featuresToUpdate.push({
            type: 'cc',
            value: features.geo_data.cc || 'XX',
            userId
          });
        }

        // 4. 处理RTT特征
        if (features.rtt !== undefined) {
          featuresToUpdate.push({
            type: 'rtt',
            value: features.rtt.toString(),
            userId
          });
        }

        // 5. 批量更新特征统计
        for (const feature of featuresToUpdate) {
          try {
            // 全局统计（不指定用户）
            await connection.execute(`
              INSERT INTO feature_stats 
                (feature_type, feature_value, user_id, count) 
              VALUES (?, ?, NULL, 1)
              ON DUPLICATE KEY UPDATE 
                count = count + 1,
                last_seen = CURRENT_TIMESTAMP
            `, [feature.type, feature.value]);

            // 如果有用户ID，则更新用户特定统计
            if (feature.userId) {
              await connection.execute(`
                INSERT INTO feature_stats 
                  (feature_type, feature_value, user_id, count) 
                VALUES (?, ?, ?, 1)
                ON DUPLICATE KEY UPDATE 
                  count = count + 1,
                  last_seen = CURRENT_TIMESTAMP
              `, [feature.type, feature.value, feature.userId]);
            }
          } catch (err) {
            console.error(`更新特征统计失败: ${feature.type}=${feature.value}`, err);
          }
        }
      } finally {
        connection.release();
      }
    } catch (error) {
      console.error('更新特征统计失败:', error);
    }
  }

  /**
   * 更新用户活动摘要表
   * @param {string} userId - 用户ID
   * @param {Object} features - 特征对象
   * @private
   */
  async _updateUserActivitySummary(userId, features) {
    try {
      const connection = await this.pool.getConnection();
      try {
        // 获取用户的最新统计
        const [ipCount] = await connection.execute(`
          SELECT COUNT(DISTINCT ip_address) as unique_ips FROM risk_logs WHERE user_id = ?
        `, [userId]);

        const [browserCount] = await connection.execute(`
          SELECT COUNT(DISTINCT JSON_EXTRACT(JSON_EXTRACT(geo_data, '$.asn'), '$')) as unique_locations,
                 COUNT(DISTINCT (
                   SELECT ua.name FROM (
                     SELECT user_agent,
                       JSON_EXTRACT(JSON_OBJECT('name', SUBSTRING_INDEX(SUBSTRING_INDEX(user_agent, '/', 1), ' ', -1)), '$.name') as name
                     FROM risk_logs LIMIT 1
                   ) as ua
                 )) as unique_browsers,
                 COUNT(DISTINCT (
                   CASE 
                     WHEN user_agent LIKE '%Mobile%' THEN 'mobile'
                     ELSE 'desktop'
                   END
                 )) as unique_devices
          FROM risk_logs WHERE user_id = ?
        `, [userId]);

        const [loginCount] = await connection.execute(`
          SELECT COUNT(*) as total FROM risk_logs WHERE user_id = ?
        `, [userId]);

        // 计算风险级别 (可以根据实际需求调整)
        let riskLevel = 0;
        if (ipCount[0].unique_ips > 3) riskLevel = 1;
        if (ipCount[0].unique_ips > 5) riskLevel = 2;

        // 更新摘要表
        await connection.execute(`
          INSERT INTO user_activity_summary 
            (user_id, total_logins, unique_ips, unique_browsers, unique_devices, unique_locations, risk_level, last_login)
          VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
          ON DUPLICATE KEY UPDATE 
            total_logins = VALUES(total_logins),
            unique_ips = VALUES(unique_ips),
            unique_browsers = VALUES(unique_browsers),
            unique_devices = VALUES(unique_devices),
            unique_locations = VALUES(unique_locations),
            risk_level = VALUES(risk_level),
            last_login = CURRENT_TIMESTAMP
        `, [
          userId, 
          loginCount[0].total, 
          ipCount[0].unique_ips,
          browserCount[0].unique_browsers || 0,
          browserCount[0].unique_devices || 0,
          browserCount[0].unique_locations || 0,
          riskLevel
        ]);
      } finally {
        connection.release();
      }
    } catch (error) {
      console.error('更新用户活动摘要失败:', error);
    }
  }

  /**
   * 更新内存中的全局和用户缓存
   * @param {string} userId - 用户ID
   * @param {Object} features - 本次事件的特征 { ip_address, geo_data, user_agent, rtt }
   * @private
   */
  _updateInMemoryCache(userId, features) {
    try {
      console.debug(`[缓存更新] 开始更新用户 ${userId} 和全局缓存`);

      const globalStats = this.cache.globalStats;
      globalStats.totalLoginCount = (globalStats.totalLoginCount || 0) + 1;

      const featureStats = globalStats.featureStats;
      const totalStats = globalStats.totalStats;

      if (features.ip_address) {
        featureStats.ip = featureStats.ip || {};
        featureStats.ip[features.ip_address] = (featureStats.ip[features.ip_address] || 0) + 1;
        totalStats.ip = (totalStats.ip || 0) + 1;
      }

      if (features.geo_data) {
        const asn = features.geo_data.asn || 'Unknown';
        const cc = features.geo_data.cc || 'XX';
        featureStats.asn = featureStats.asn || {};
        featureStats.cc = featureStats.cc || {};
        featureStats.asn[asn] = (featureStats.asn[asn] || 0) + 1;
        featureStats.cc[cc] = (featureStats.cc[cc] || 0) + 1;
        totalStats.asn = (totalStats.asn || 0) + 1;
        totalStats.cc = (totalStats.cc || 0) + 1;
      }

      if (features.user_agent) {
        const UAParser = require('ua-parser-js');
        const parser = new UAParser(features.user_agent);
        const browser = parser.getBrowser();
        const os = parser.getOS();
        const device = parser.getDevice();

        const uaName = browser.name || 'Unknown';
        const bv = this._parseVersion(browser.version);
        const osv = os.version || 'Unknown';
        const df = device.model ? device.model : 'desktop';

        featureStats.ua = featureStats.ua || {};
        featureStats.bv = featureStats.bv || {};
        featureStats.osv = featureStats.osv || {};
        featureStats.df = featureStats.df || {};

        featureStats.ua[uaName] = (featureStats.ua[uaName] || 0) + 1;
        featureStats.bv[bv] = (featureStats.bv[bv] || 0) + 1;
        featureStats.osv[osv] = (featureStats.osv[osv] || 0) + 1;
        featureStats.df[df] = (featureStats.df[df] || 0) + 1;

        totalStats.ua = (totalStats.ua || 0) + 1;
        totalStats.bv = (totalStats.bv || 0) + 1;
        totalStats.osv = (totalStats.osv || 0) + 1;
        totalStats.df = (totalStats.df || 0) + 1;
      }

      if (features.rtt !== undefined) {
        featureStats.rtt = featureStats.rtt || {};
        featureStats.rtt[features.rtt] = (featureStats.rtt[features.rtt] || 0) + 1;
        totalStats.rtt = (totalStats.rtt || 0) + 1;
      }

      // 更新用户历史记录（如果用户存在）
      if (this.users[userId]) {
        const userHistory = this.users[userId];
        userHistory.loginCount = (userHistory.loginCount || 0) + 1;

        // 确保用户特征和总数结构存在
        userHistory.features = userHistory.features || {};
        userHistory.total = userHistory.total || {};

        if (features.ip_address) {
          userHistory.features.ip = userHistory.features.ip || {};
          userHistory.features.ip[features.ip_address] = (userHistory.features.ip[features.ip_address] || 0) + 1;
          userHistory.total.ip = (userHistory.total.ip || 0) + 1;
        }

        if (features.geo_data) {
          const asn = features.geo_data.asn || 'Unknown';
          const cc = features.geo_data.cc || 'XX';
          userHistory.features.asn = userHistory.features.asn || {};
          userHistory.features.cc = userHistory.features.cc || {};
          userHistory.features.asn[asn] = (userHistory.features.asn[asn] || 0) + 1;
          userHistory.features.cc[cc] = (userHistory.features.cc[cc] || 0) + 1;
          userHistory.total.asn = (userHistory.total.asn || 0) + 1;
          userHistory.total.cc = (userHistory.total.cc || 0) + 1;
        }

        if (features.user_agent) {
          const UAParser = require('ua-parser-js');
          const parser = new UAParser(features.user_agent);
          const browser = parser.getBrowser();
          const os = parser.getOS();
          const device = parser.getDevice();

          const uaName = browser.name || 'Unknown';
          const bv = this._parseVersion(browser.version);
          const osv = os.version || 'Unknown';
          const df = device.model ? device.model : 'desktop';

          userHistory.features.ua = userHistory.features.ua || {};
          userHistory.features.bv = userHistory.features.bv || {};
          userHistory.features.osv = userHistory.features.osv || {};
          userHistory.features.df = userHistory.features.df || {};

          userHistory.features.ua[uaName] = (userHistory.features.ua[uaName] || 0) + 1;
          userHistory.features.bv[bv] = (userHistory.features.bv[bv] || 0) + 1;
          userHistory.features.osv[osv] = (userHistory.features.osv[osv] || 0) + 1;
          userHistory.features.df[df] = (userHistory.features.df[df] || 0) + 1;

          userHistory.total.ua = (userHistory.total.ua || 0) + 1;
          userHistory.total.bv = (userHistory.total.bv || 0) + 1;
          userHistory.total.osv = (userHistory.total.osv || 0) + 1;
          userHistory.total.df = (userHistory.total.df || 0) + 1;
        }

        if (features.rtt !== undefined) {
          userHistory.features.rtt = userHistory.features.rtt || {};
          userHistory.features.rtt[features.rtt] = (userHistory.features.rtt[features.rtt] || 0) + 1;
          userHistory.total.rtt = (userHistory.total.rtt || 0) + 1;
        }
      } else {
        console.debug(`[缓存更新] 用户 ${userId} 不在缓存中，将在下次请求时初始化`);
      }

      console.debug(`[缓存更新] 完成`);
    } catch (error) {
      console.error(`[缓存更新失败] 用户 ${userId}:`, error);
    }
  }

  _parseVersion(version) {
    if (!version) return '0.0.0';
    return version.split('.').slice(0, 3).join('.');
  }

  handleDBError(error, message) {
    console.error(`[数据库错误] ${message}:`, error);
  }
}

// 创建单例实例（供中间件使用）
const historyStoreInstance = new HistoryStore();

// 修改中间件挂载方式
module.exports = {
  instance: historyStoreInstance,
  middleware: (req, res, next) => {
    req.historyStore = historyStoreInstance;
    if (req.path === '/login' && req.method === 'POST') {
      const userId = req.body?.username || req.user?.id;
      if (userId) {
        historyStoreInstance.initializeUserHistory(userId, true)
          .catch(err => console.error('用户历史初始化失败:', err));
      }
    }
    next();
  }
};

