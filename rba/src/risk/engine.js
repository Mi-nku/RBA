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
        const { globalHistory, userHistory } = await this._getHistories(userId);


        // 新增调试日志头
        console.debug(`[风险计算] 用户 ${userId} 开始风险评估`, {
            globalLoginCount: globalHistory.loginCount,
            userLoginCount: userHistory.loginCount
        });
    
        // 遍历所有主特征
        for (const mainFeature of Object.keys(config.coefficients)) {
            const featureValue = this._parseFeature(mainFeature, features);

            console.debug(`[特征处理] 主特征 ${mainFeature} 解析结果:`, JSON.stringify(featureValue));
    
            // ===================== 攻击者概率 p_A_given_xk =====================
            let pA = 1.0;
            for (const [subFeature, weight] of Object.entries(config.coefficients[mainFeature])) {
                const subValue = this._parseSubFeature(subFeature, featureValue);
                
                // 子特征攻击概率判断
                let subRisk;
                switch (subFeature) {
                    case 'asn':
        subRisk = subValue === 'Local' ? 0.01 :  // ← 在此处添加
            this.maliciousNetworks.includes(subValue) ? 0.9 : 0.1;
        break;
    case 'cc':
        subRisk = subValue === 'LOCAL' ? 0.01 :  // ← 在此处添加
            config.maliciousCountries.includes(subValue) ? 0.8 : 0.2;
        break;
                    case 'asn':
                        subRisk = this.maliciousNetworks.includes(subValue) ? 0.9 : 0.1;
                        break;
                    case 'cc':
                        subRisk = config.maliciousCountries.includes(subValue) ? 0.8 : 0.2;
                        break;
                    case 'bv':
                        const minVersion = config.minBrowserVersion[featureValue.ua] || 70;
                        subRisk = parseInt(subValue) < minVersion ? 0.7 : 0.1;
                        break;
                    default:
                        subRisk = 0.5;
                }
                pA *= subRisk; // 各子特征攻击概率相乘

                // 新增子特征日志
                console.debug(`[攻击者概率] 特征 ${mainFeature}.${subFeature}`, {
                    subValue: subValue.toString(),
                    subRisk: subRisk.toFixed(2),
                    currentPA: pA.toFixed(4)
                });
            }
    
            // ===================== 全局概率 p_xk =====================
            let pXk = 1.0;
            for (const [subFeature, weight] of Object.entries(config.coefficients[mainFeature])) {
                const subValue = this._parseSubFeature(subFeature, featureValue);
                const globalCount = globalHistory.features[subFeature]?.[subValue] || 0;
                const globalTotal = globalHistory.total[subFeature] || 1;
                const pHistory = this._smooth(globalCount, globalTotal);
                pXk *= pHistory; // 各子特征全局概率相乘

                // 新增全局概率日志
            console.debug(`[全局概率] 特征 ${mainFeature}.${subFeature}`, {
                subValue: subValue.toString(),
                globalCount,
                globalTotal,
                pHistory: pHistory.toFixed(4),
                currentPXk: pXk.toFixed(4)
            });



            }
    
            // ===================== 用户本地概率 p_xk_given_u_L =====================
            let pXkL = 1.0;
            for (const [subFeature, weight] of Object.entries(config.coefficients[mainFeature])) {
                const subValue = this._parseSubFeature(subFeature, featureValue);
                const userCount = userHistory.features[subFeature]?.[subValue] || 0;
                const userTotal = userHistory.total[mainFeature] || 1;
                const userProb = this._smooth(userCount, userTotal);
                pXkL *= userProb; // 各子特征用户概率相乘


                // 新增用户概率日志
            console.debug(`[用户概率] 特征 ${mainFeature}.${subFeature}`, {
                subValue: subValue.toString(),
                userCount,
                userTotal,
                userProb: userProb.toFixed(4),
                currentPXkL: pXkL.toFixed(4)
            });
            }
    
            // ===================== 特征贡献值 =====================
            const beforeScore = score;
        score *= (pA * pXk) / Math.max(pXkL, 0.01);
        console.debug(`[特征贡献] ${mainFeature}`, {
            pA: pA.toFixed(4),
            pXk: pXk.toFixed(4),
            pXkL: pXkL.toFixed(4),
            contribution: (score / beforeScore).toFixed(4),
            newScore: score.toFixed(4)
        });
        }
    
        // ===================== 全局用户比例调整 p_u_given_A / p_u_given_L =====================
        const totalUsers = Object.keys(this.history.users).length || 1;
        const pUGivenA = 1 / totalUsers; // 攻击者中该用户的概率
        const pUGivenL = userHistory.loginCount / globalHistory.loginCount || 0.01; // 正常用户中该用户的活跃度
        

        // 新增比例调整日志
    console.debug(`[比例调整] 用户 ${userId}`, {
        totalUsers,
        pUGivenA: pUGivenA.toExponential(2),
        pUGivenL: pUGivenL.toExponential(2),
        ratio: (pUGivenA / pUGivenL).toExponential(2)
    });



        // 修改 calculate 方法中的 finalScore 计算
        let finalScore = Number(score * (pUGivenA / pUGivenL));
        if (isNaN(finalScore)) {
           console.error('风险评估异常: 最终分数为 NaN', { score, pUGivenA, pUGivenL });
           finalScore = 1.0; // 默认安全值
        }
        finalScore = Math.min(finalScore, 1.0);
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
        }
    
        // ===================== 保存完整日志 =====================
        await query(
            `INSERT INTO risk_logs 
            (user_id, ip_address, user_agent, geo_data, risk_score, action) 
            VALUES (?, ?, ?, ?, ?, ?)`,
            [
                userId,
                features.ip || '0.0.0.0', // 处理 ip 缺失
                features.userAgent || 'Unknown',
                JSON.stringify(geoData || {}), // 处理 geoData 未定义
                finalScore,
                action
            ]
        );
    
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

        // 新增本地IP白名单判断
      if(['::1', '127.0.0.1'].includes(ip)) {
        return { ip, asn: 'Local', cc: 'LOCAL' }; // 明确标记为本地
      }
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
      const parser = new UAParser(userAgent);
      const browser = parser.getBrowser();
      const os = parser.getOS();
      const device = parser.getDevice();
      
      return {
        ua: browser.name || 'Unknown',
        bv: this._parseVersion(browser.version), // 新增版本号格式化
        osv: os.version || 'Unknown',
        df: device.model ? device.model : 'desktop' // 设备信息兜底
      };
    } catch (e) {
      return { ua: 'Unknown', bv: '0.0.0', osv: 'Unknown', df: 'unknown' };
    }
  }

  // 新增版本号格式化方法
  _parseVersion(version) {
    if (!version) return '0.0.0';
    return version.split('.').slice(0,3).join('.');
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
            loginCount: this.history.getTotalLoginCount() || 1, // 防止除零错误
            features: this.history.getGlobalFeatureStats(),     // 全局特征统计
            total: this.history.getGlobalTotalStats()          // 全局总计数
        };

        // 获取用户特定历史
        let userHistory = this.history.users[userId];
        if (!userHistory) {
            console.warn('[风险引擎] 用户首次登录，初始化历史记录', { userId });
            userHistory = {
                loginCount: 0,
                features: this._initFeatureStats(), // 初始化空特征统计
                total: this._initTotalStats()       // 初始化空总计数
            };
            this.history.users[userId] = userHistory;
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
