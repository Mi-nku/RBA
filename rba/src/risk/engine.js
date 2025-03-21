const config = require('./config.js');
const { query } = require('./database.js');
const geoip = require('geoip-lite'); // 需要安装 geoip-lite 库
const UAParser = require('ua-parser-js'); // 需要安装 ua-parser-js 库

class RiskEngine {
    

    constructor(historyStore) {
        // 验证 historyStore 实例
        console.log('[RiskEngine 初始化] 开始验证 historyStore 实例');
        console.log('historyStore 类型:', typeof historyStore);
        console.log('historyStore 方法检查:', {
            getTotalLoginCount: typeof historyStore?.getTotalLoginCount,
            getGlobalFeatureStats: typeof historyStore?.getGlobalFeatureStats,
            users: historyStore?.users ? '已初始化' : '未定义'
        });

        // 深度验证（生产环境慎用，此处仅用于调试）
        try {
            console.log('historyStore 实例结构:', JSON.stringify(Object.keys(historyStore), null, 2));
        } catch (err) {
            console.error('historyStore 实例无法序列化（可能包含循环引用）');
        }

        this.history = historyStore;
        this.maliciousNetworks = [];

        // 最终验证结果
        if (
            typeof this.history.getTotalLoginCount === 'function' &&
            typeof this.history.getGlobalFeatureStats === 'function' &&
            this.history.users !== undefined
        ) {
            console.log('[✅] historyStore 验证通过');
        } else {
            console.error('[❌] historyStore 验证失败，请检查：');
            console.error('1. 是否传递了正确的 historyStore 实例');
            console.error('2. historyStore 是否实现了必需的方法');
            throw new Error('Invalid historyStore instance');
        }
    }



    

    /**
     * 带安全保护的平滑函数
     */
    _smooth(count, total) {
        if (total === 0) return 0.5;
        const alpha = config.smoothingAlpha || 1;
        return (count + alpha) / (total + alpha * 2);
    }

    /**
     * 安全解析子特征值
     */
    _parseSubFeature(subFeature, featureValue) {
        const keys = subFeature.split('.');
        let value = featureValue;
        for (const key of keys) {
            value = value?.[key];
            if (value === undefined) break;
        }
        return (value ?? 'unknown').toString().trim();
    }



  



    async calculate(userId, features) {
        let geoData = null;
        let score = 1.0;
        
        // 验证输入参数
        console.log(`\n========== 风险计算开始 [用户ID: ${userId}] ==========`);
        console.log(`原始输入特征:`, features);
        
        // 验证 userAgent 是否存在
        if (!features.userAgent && features.ua) {
            console.log('修正: 使用 features.ua 作为 userAgent');
            features.userAgent = features.ua;
        }
        
        // 确保 IP 地址格式正确
        if (features.ip && features.ip.startsWith('::ffff:')) {
            console.log('IPv6 映射的 IPv4 地址:', features.ip);
        }
        
        console.log(`处理后的输入特征:`, JSON.stringify(features, null, 2));
        
        const { globalHistory, userHistory } = await this._getHistories(userId);
    
        console.log(`\n========== 风险计算开始 [用户ID: ${userId}] ==========`);
        console.log(`输入特征数据:`, JSON.stringify(features, null, 2));
        
        // 遍历所有主特征
        for (const mainFeature of Object.keys(config.coefficients)) {
            const featureValue = this._parseFeature(mainFeature, features);
            console.log(`\n----- 主特征: ${mainFeature} -----`);
            console.log(`解析后的特征值:`, JSON.stringify(featureValue, null, 2));
    
            // ===================== 攻击者概率 p_A_given_xk =====================
            let pA = 1.0;
            console.log(`\n子特征攻击概率计算:`);
            for (const [subFeature, weight] of Object.entries(config.coefficients[mainFeature])) {
                const subValue = this._parseSubFeature(subFeature, featureValue);
                
                // 子特征攻击概率判断
                let subRisk;
                switch (subFeature) {
                    case 'asn':
                        subRisk = this.maliciousNetworks.includes(subValue) ? 0.9 : 0.1;
                        console.log(`  - ${subFeature}: ${subValue} (${this.maliciousNetworks.includes(subValue) ? '恶意网络' : '正常网络'}) => ${subRisk}`);
                        break;
                    case 'cc':
                        subRisk = config.maliciousCountries.includes(subValue) ? 0.8 : 0.2;
                        console.log(`  - ${subFeature}: ${subValue} (${config.maliciousCountries.includes(subValue) ? '高风险国家' : '正常国家'}) => ${subRisk}`);
                        break;
                    case 'bv':
                        const minVersion = config.minBrowserVersion[featureValue.ua] || 70;
                        subRisk = parseInt(subValue) < minVersion ? 0.7 : 0.1;
                        console.log(`  - ${subFeature}: ${subValue} (最低要求: ${minVersion}) => ${subRisk}`);
                        break;
                    default:
                        subRisk = 0.5;
                        console.log(`  - ${subFeature}: ${subValue} (默认风险) => ${subRisk}`);
                }
                pA *= subRisk; // 各子特征攻击概率相乘
            }
            console.log(`  攻击者概率 pA = ${pA.toFixed(4)}`);
    
            // ===================== 全局概率 p_xk =====================
            let pXk = 1.0;
            console.log(`\n全局概率计算:`);
            for (const [subFeature, weight] of Object.entries(config.coefficients[mainFeature])) {
                const subValue = this._parseSubFeature(subFeature, featureValue);
                const globalCount = globalHistory.features[subFeature]?.[subValue] || 0;
                const globalTotal = globalHistory.total[subFeature] || 1;
                const pHistory = this._smooth(globalCount, globalTotal);
                console.log(`  - ${subFeature}: ${subValue} (出现次数: ${globalCount}/${globalTotal}) => ${pHistory.toFixed(4)}`);
                pXk *= pHistory; // 各子特征全局概率相乘
            }
            console.log(`  全局概率 pXk = ${pXk.toFixed(4)}`);
    
            // ===================== 用户本地概率 p_xk_given_u_L =====================
            let pXkL = 1.0;
            console.log(`\n用户本地概率计算:`);
            for (const [subFeature, weight] of Object.entries(config.coefficients[mainFeature])) {
                const subValue = this._parseSubFeature(subFeature, featureValue);
                const userCount = userHistory.features[subFeature]?.[subValue] || 0;
                const userTotal = userHistory.total[mainFeature] || 1;
                const userProb = this._smooth(userCount, userTotal);
                console.log(`  - ${subFeature}: ${subValue} (用户历史: ${userCount}/${userTotal}) => ${userProb.toFixed(4)}`);
                pXkL *= userProb; // 各子特征用户概率相乘
            }
            console.log(`  用户本地概率 pXkL = ${pXkL.toFixed(4)}`);
    
            // ===================== 特征贡献值 =====================
            const featureContribution = (pA * pXk) / Math.max(pXkL, 0.01);
            console.log(`\n特征 ${mainFeature} 贡献值 = ${featureContribution.toFixed(4)}`);
            score *= featureContribution;
            console.log(`当前累积分数 = ${score.toFixed(4)}`);
        }
    
        // ===================== 全局用户比例调整 p_u_given_A / p_u_given_L =====================
        const totalUsers = Object.keys(this.history.users).length || 1;
        const pUGivenA = 1 / totalUsers; // 攻击者中该用户的概率
        const pUGivenL = userHistory.loginCount / globalHistory.loginCount || 0.01; // 正常用户中该用户的活跃度
        
        console.log(`\n用户活跃度调整:`);
        console.log(`  - 总用户数: ${totalUsers}`);
        console.log(`  - 用户登录次数: ${userHistory.loginCount || 0}`);
        console.log(`  - 全局登录总次数: ${globalHistory.loginCount}`);
        console.log(`  - pUGivenA (攻击者中该用户概率): ${pUGivenA.toFixed(4)}`);
        console.log(`  - pUGivenL (正常用户中该用户活跃度): ${pUGivenL.toFixed(4)}`);
        
        // 修改 calculate 方法中的 finalScore 计算
        let finalScore = Number(score * (pUGivenA / pUGivenL));
        if (isNaN(finalScore)) {
           console.error('风险评估异常: 最终分数为 NaN', { score, pUGivenA, pUGivenL });
           finalScore = 1.0; // 默认安全值
        }
        finalScore = Math.min(finalScore, 1.0);
        console.log(`\n最终风险分数: ${finalScore.toFixed(4)}`);
        
        // ===================== 阈值判断 =====================
        const rejectThreshold = config.risk.rejectThreshold || 0.7;
        const requestThreshold = config.risk.requestThreshold || 0.4;
        let action = 'ALLOW';
    
        if (finalScore > rejectThreshold) {
            action = 'REJECT';
            console.error(`[风险拒绝] 用户 ${userId} 分数: ${finalScore.toFixed(2)}`);
        } else if (finalScore > requestThreshold) {
            action = 'CHALLENGE';
            console.warn(`[需要验证] 用户 ${userId} 分数: ${finalScore.toFixed(2)}`);
        } else {
            console.log(`[允许访问] 用户 ${userId} 分数: ${finalScore.toFixed(2)}`);
        }
        console.log(`========== 风险计算结束 [行动: ${action}] ==========\n`);
    
        // // ===================== 保存完整日志 =====================
        // await query(
        //     `INSERT INTO risk_logs 
        //     (user_id, ip_address, user_agent, geo_data, risk_score, action) 
        //     VALUES (?, ?, ?, ?, ?, ?)`,
        //     [
        //         userId,
        //         features.ip || '0.0.0.0', // 处理 ip 缺失
        //         features.userAgent || 'Unknown',
        //         JSON.stringify(geoData || {}), // 处理 geoData 未定义
        //         finalScore,
        //         action
        //     ]
        // );
    
        return {
            score: finalScore,
            action: action
        };
    }






    // 风险历史查询
    async getUserRiskHistory(userId) {
        return query(
            `SELECT * FROM risk_logs 
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 50`,
            [userId]
        );
    }

     /**
   * 解析 IP 地址信息
   * @param {string} ip - IP 地址
   * @returns {Object} { ip, asn, cc }
   */
  parseIP(ip) {
    try {
      const geo = geoip.lookup(ip);
      if(ip=='::1'){
        return{
            ip,
        asn: geo?.asn || 'Unknown',  // 自治系统号
        cc: geo?.country || 'XX'  
        };
      }
      return {
        ip,
        asn: geo?.asn || 'Unknown',  // 自治系统号
        cc: geo?.country || 'XX'      // 国家代码
      };
    } catch (error) {
      console.error('IP 解析失败:', ip, error);
      return { ip, asn: 'Unknown', cc: 'XX' };
    }
  }


  /**
   * 解析 User-Agent 信息
   * @param {string} userAgent - 浏览器 User-Agent 字符串
   * @returns {Object} { ua, bv, osv }
   */
  _parseUA(userAgent) {
    try {
      console.log('正在解析 UA:', userAgent);
      
      if (!userAgent || typeof userAgent !== 'string') {
        console.error('无效的 User-Agent:', userAgent);
        return { ua: 'Unknown', bv: '0.0.0', osv: 'Unknown' };
      }
      
      const parser = new UAParser(userAgent);
      const result = parser.getResult();
      const browser = result.browser;
      const os = result.os;
      
      console.log('UA 解析结果:', {
        browser: browser,
        os: os,
        engine: result.engine,
        device: result.device,
        cpu: result.cpu
      });
      
      // 处理特殊情况：Electron 应用
      if (userAgent.includes('Electron')) {
        // 尝试从 UA 中提取 Chrome 版本
        const chromeMatch = userAgent.match(/Chrome\/(\d+\.\d+\.\d+\.\d+)/);
        const electronMatch = userAgent.match(/Electron\/(\d+\.\d+\.\d+)/);
        
        // 尝试提取自定义应用名称（如 Trae）
        const customAppMatch = userAgent.match(/ ([A-Za-z]+)\/(\d+\.\d+\.\d+) /);
        
        const browserName = customAppMatch ? customAppMatch[1] : 'Electron';
        const browserVersion = chromeMatch ? chromeMatch[1] : (browser.version || '0.0.0');
        
        console.log('检测到 Electron 应用:', {
          name: browserName,
          version: browserVersion,
          electronVersion: electronMatch ? electronMatch[1] : 'unknown'
        });
        
        return {
          ua: browserName,
          bv: browserVersion.split('.')[0] || '0', // 只取主版本号
          osv: os.version || 'Unknown'
        };
      }
      
      // 标准浏览器
      return {
        ua: browser.name || 'Unknown',
        bv: browser.version ? browser.version.split('.')[0] : '0', // 只取主版本号
        osv: os.version || 'Unknown'
      };
    } catch (error) {
      console.error('UA 解析失败:', userAgent, error);
      return { ua: 'Unknown', bv: '0.0.0', osv: 'Unknown' };
    }
  }
    // 特征解析（IP/UA等）
    _parseFeature(feature, data) {
        switch (feature) {
            case 'ip':
                return data.ip ? this.parseIP(data.ip) : { ip: 'Unknown', asn: 'Unknown', cc: 'XX' };
            case 'ua':
                return this._parseUA(data.userAgent); // 返回{ ua, bv, osv }
            case 'rtt':
                return data.rtt;
            default:
                return data[feature];
        }
    }

    _calcGlobalProb(feature, value, history) {
        const counter = history.features[feature][value] || 0;
        const total = history.total[feature] || 1;
        return this._smooth(counter, total);
    }

    async _getHistories(userId) {
        // 获取全局登录历史（所有用户）
        const globalHistory = {
            loginCount: await this.history.getTotalLoginCount() || 1, // 防止除零错误
            features: await this.history.getGlobalFeatureStats(),     // 全局特征统计
            total: await this.history.getGlobalTotalStats()          // 全局总计数
        };
    
        // 获取用户特定历史
        let userHistory = this.history.users[userId];
        if (!userHistory) {
            console.warn('[风险引擎] 内存中无用户历史，尝试从数据库加载', { userId });
            
            // 尝试从数据库初始化用户历史
            try {
                const result = await this.history.initializeUserHistory(userId);
                if (result) {
                    userHistory = this.history.users[userId];
                    console.log('[风险引擎] 从数据库加载用户历史成功', { userId, loginCount: userHistory.loginCount });
                } else {
                    console.warn('[风险引擎] 数据库中无用户历史记录', { userId });
                }
            } catch (err) {
                console.error('[风险引擎] 从数据库加载用户历史失败', err);
            }
            
            // 如果数据库中也没有或加载失败，则创建新的历史记录
            if (!userHistory) {
                console.warn('[风险引擎] 用户首次登录，初始化历史记录', { userId });
                userHistory = {
                    loginCount: 0,
                    features: this._initFeatureStats(), // 初始化空特征统计
                    total: this._initTotalStats()       // 初始化空总计数
                };
                this.history.users[userId] = userHistory;
            }
        }
    
        return {
            globalHistory,
            userHistory
        };
    }

    // 辅助方法：初始化特征统计结构
    _initFeatureStats() {
        return Object.keys(config.coefficients).reduce((acc, feature) => {
            acc[feature] = {};
            return acc;
        }, {});
    }

    // 辅助方法：初始化总计数结构
    _initTotalStats() {
        return Object.keys(config.coefficients).reduce((acc, feature) => {
            acc[feature] = 0;
            return acc;
        }, {});
    }

}

module.exports = RiskEngine;