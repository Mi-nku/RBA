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
        this.maliciousNetworks = ['AS12345', 'AS67890']; // 高风险ASN列表

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
        const alpha = 1; // 严格使用Python版本拉普拉斯平滑参数
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
     * 计算用户本地概率 - 参考core.py中的p_xk_given_u_L方法
     */
    _calculateUserProbability(feature, value, userHistory) {
        // 获取特征的所有值出现次数总和
        const featureValues = userHistory.features[feature] || {};
        const totalOccurrences = Object.values(featureValues).reduce((sum, count) => sum + count, 0);

        // 获取特定值的出现次数
        const valueOccurrences = featureValues[value] || 0;

        // 使用平滑处理
        return this._smoothProbability(valueOccurrences, totalOccurrences);
    }

    /**
     * 平滑概率计算 - 参考core.py中的p_0方法
     */
    _smoothProbability(count, total, alpha = 1) {
        if (total === 0) return 0.5;

        // 拉普拉斯平滑
        return (count + alpha) / (total + alpha * 2);
    }
    /**
  * 解析 IP 地址信息
  * @param {string} ip - IP 地址
  * @returns {Object} { ip, asn, cc }
  */
    parseIP(ip) {
        try {

            // 新增本地IP白名单判断
            if (['::1', '127.0.0.1'].includes(ip)) {
                return { ip, asn: 'Local', cc: 'LOCAL' }; // 明确标记为本地
            }
            const geo = geoip.lookup(ip);
            if (ip == '::1') {
                return {
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
        return version.split('.').slice(0, 3).join('.');
    }
    // 特征解析（IP/UA等）
    _parseFeature(feature, data) {
        switch (feature) {
            case 'ip':
                return data.ip ? this.parseIP(data.ip) : { ip: 'Unknown', asn: 'Unknown', cc: 'XX' };
            case 'ua':
                // 修改这里，同时支持ua和userAgent字段
                const userAgentString = data.userAgent || data.ua || 'Unknown';
                return this._parseUA(userAgentString); // 返回{ ua, bv, osv }
            case 'rtt':
                return parseFloat(data.rtt) || 0;
            default:
                return data[feature];
        }
    }

    _calcGlobalProb(feature, value, history) {
        // 重构概率计算逻辑与core.py的p_k方法一致
        const [mainFeature, subFeature] = feature.split('.');
        let counter = 0;
        let total = 0;
        
        // 获取正确的特征值用于查询历史记录
        let lookupValue;
        if (feature === 'ip' && typeof value === 'object') {
            lookupValue = value.ip; // 使用IP地址字符串
        } else if (feature === 'ua' && typeof value === 'object') {
            lookupValue = value.ua; // 使用浏览器名称字符串
        } else if (feature === 'rtt' && typeof value === 'number') {
            // 对RTT进行格式化，确保与历史记录中的格式一致
            lookupValue = value.toFixed(3);
        } else if (typeof value === 'object' && value[feature]) {
            lookupValue = value[feature];
        } else {
            lookupValue = value;
        }

        // 检查是否为复合特征（如 ip.asn, ua.bv 等）
        if (feature.includes('.')) {
            const [mainFeature, subFeature] = feature.split('.');
            if (mainFeature === 'ip') {
                // 对于 ip.asn 和 ip.cc，total 应该从对应的 subFeature 获取
                if (subFeature === 'asn' || subFeature === 'cc') {
                    counter = history.globalStats.featureStats[subFeature]?.[lookupValue] || 0;
                    total = history.globalStats.totalStats[subFeature] || 0;
                } else {
                    counter = history.globalStats.featureStats.ip?.[subFeature]?.[lookupValue] || 0;
                    total = history.globalStats.totalStats.ip?.[subFeature] || 0;
                }
            } else if (mainFeature === 'ua') {
                counter = history.globalStats.featureStats.ua?.[subFeature]?.[lookupValue] || 0;
                // 修正：total 应该从扁平的 totalStats 中获取，而不是嵌套的 ua?.[subFeature]
                total = history.globalStats.totalStats[subFeature] || 0;
            } else { // 非复合特征，如 rtt
                counter = history.globalStats.featureStats[feature]?.[lookupValue] || 0;
                total = history.globalStats.totalStats[feature] || 0;
            }
        } else { // 单一特征，如 ip, ua, rtt
            counter = history.globalStats.featureStats[feature]?.[lookupValue] || 0;
            // 修正：单一特征的 total 应该直接从 totalStats 中获取
            total = history.globalStats.totalStats[feature] || 0;
        }

        console.debug(`[全局概率] 特征 ${feature} 查询:`, {
            lookupValue,
            counter,
            total
        });

        // 使用平滑处理
        return this._smoothProbability(counter, total);
    }

    /**
     * 获取全局和用户历史数据
     * @param {string} userId - 用户ID
     * @returns {Promise<Object>} - 全局和用户历史数据
     * @private
     */
    async _getHistories(userId) {
        console.debug(`[风险引擎] 开始获取历史数据: ${userId}`);

        // 获取全局登录历史（所有用户）
        const globalLoginCount = await this.history.getTotalLoginCount() || 1;
        const globalFeatures = await this.history.getGlobalFeatureStats() || {};
        const globalTotals = await this.history.getGlobalTotalStats() || {};

        // 构建正确的全局历史结构
        const globalHistory = {
            loginCount: globalLoginCount,
            globalStats: {
                featureStats: globalFeatures,
                totalStats: globalTotals
            }
        };

        // 确保所有特征对象都存在，防止空引用错误
        if (!globalHistory.globalStats.featureStats.ip) globalHistory.globalStats.featureStats.ip = {};
        if (!globalHistory.globalStats.featureStats.asn) globalHistory.globalStats.featureStats.asn = {};
        if (!globalHistory.globalStats.featureStats.cc) globalHistory.globalStats.featureStats.cc = {};
        if (!globalHistory.globalStats.featureStats.ua) globalHistory.globalStats.featureStats.ua = {};
        if (!globalHistory.globalStats.featureStats.bv) globalHistory.globalStats.featureStats.bv = {};
        if (!globalHistory.globalStats.featureStats.osv) globalHistory.globalStats.featureStats.osv = {};
        if (!globalHistory.globalStats.featureStats.df) globalHistory.globalStats.featureStats.df = {};
        if (!globalHistory.globalStats.featureStats.rtt) globalHistory.globalStats.featureStats.rtt = {};

        // 调试日志：检查全局特征统计
        console.debug('[全局特征统计]', {
            loginCount: globalHistory.loginCount,
            featureKeys: Object.keys(globalHistory.globalStats.featureStats),
            totalKeys: Object.keys(globalHistory.globalStats.totalStats),
            ipSampleCount: Object.keys(globalHistory.globalStats.featureStats.ip || {}).length,
            asnSampleCount: Object.keys(globalHistory.globalStats.featureStats.asn || {}).length,
            ccSampleCount: Object.keys(globalHistory.globalStats.featureStats.cc || {}).length,
            uaSampleCount: Object.keys(globalHistory.globalStats.featureStats.ua || {}).length,
            bvSampleCount: Object.keys(globalHistory.globalStats.featureStats.bv || {}).length,
            osvSampleCount: Object.keys(globalHistory.globalStats.featureStats.osv || {}).length,
            dfSampleCount: Object.keys(globalHistory.globalStats.featureStats.df || {}).length,
            rttSampleCount: Object.keys(globalHistory.globalStats.featureStats.rtt || {}).length // 新增RTT计数
        });

        // 强制从数据库获取最新的用户历史数据
        let userHistory = await this.history.initializeUserHistory(userId);

        if (!userHistory || !userHistory.loginCount) {
            console.warn('[风险引擎] 用户首次登录或历史记录为空', { userId });
            userHistory = {
                loginCount: 0,
                features: { ip: {}, ua: {}, bv: {}, osv: {}, df: {}, asn: {}, cc: {}, rtt: {} },
                total: { ip: 0, ua: 0, asn: 0, cc: 0, bv: 0, osv: 0, df: 0, rtt: 0 }
            };
            this.history.users[userId] = userHistory;
        }
        // 无论是否首次登录，都尝试修复用户历史记录中的总计数，确保数据一致性
        this._fixUserHistoryTotals(userHistory);

        // 调试日志：检查用户特征统计
        console.debug('[用户特征统计]', {
            userId,
            loginCount: userHistory.loginCount,
            featureKeys: Object.keys(userHistory.features),
            totalKeys: Object.keys(userHistory.total),
            ipCount: Object.keys(userHistory.features.ip || {}).length,
            uaCount: Object.keys(userHistory.features.ua || {}).length,
            asnCount: Object.keys(userHistory.features.asn || {}).length, // 新增ASN计数
            ccCount: Object.keys(userHistory.features.cc || {}).length,   // 新增CC计数
            bvCount: Object.keys(userHistory.features.bv || {}).length,   // 新增BV计数
            osvCount: Object.keys(userHistory.features.osv || {}).length, // 新增OSV计数
            dfCount: Object.keys(userHistory.features.df || {}).length,   // 新增DF计数
            rttCount: Object.keys(userHistory.features.rtt || {}).length, // 新增RTT计数
            features: userHistory.features // 完整输出 features 对象
        });

        return {
            globalHistory,
            userHistory
        };
    }

    /**
     * 修复用户历史记录中的总计数
     * @param {Object} userHistory - 用户历史记录
     */
    _fixUserHistoryTotals(userHistory) {
        try {
            // 修复IP相关特征的总计数
            userHistory.total.ip = Object.values(userHistory.features.ip || {}).reduce((sum, count) => sum + count, 0);
            userHistory.total.asn = Object.values(userHistory.features.asn || {}).reduce((sum, count) => sum + count, 0);
            userHistory.total.cc = Object.values(userHistory.features.cc || {}).reduce((sum, count) => sum + count, 0);

            // 修复UA相关特征的总计数
            userHistory.total.ua = Object.values(userHistory.features.ua || {}).reduce((sum, count) => sum + count, 0);
            userHistory.total.bv = Object.values(userHistory.features.bv || {}).reduce((sum, count) => sum + count, 0);
            userHistory.total.osv = Object.values(userHistory.features.osv || {}).reduce((sum, count) => sum + count, 0);
            userHistory.total.df = Object.values(userHistory.features.df || {}).reduce((sum, count) => sum + count, 0);
            userHistory.total.rtt = Object.values(userHistory.features.rtt || {}).reduce((sum, count) => sum + count, 0);

            console.debug('[用户历史] 总计数修复完成', {
                ip: userHistory.total.ip,
                ua: userHistory.total.ua,
                bv: userHistory.total.bv,
                osv: userHistory.total.osv,
                df: userHistory.total.df,
                asn: userHistory.total.asn,
                cc: userHistory.total.cc,
                rtt: userHistory.total.rtt
            });
        } catch (error) {
            console.error('[用户历史] 总计数修复失败', error);
        }
    }

    // 辅助方法：初始化特征统计结构 - 修改为正确的嵌套结构
    _initFeatureStats() {
        const features = {};

        // 为每个主特征创建空对象
        for (const mainFeature of Object.keys(config.coefficients)) {
            features[mainFeature] = {}; // 初始化主特征
            // 为每个子特征创建空对象
            for (const subFeature of Object.keys(config.coefficients[mainFeature])) {
                // 确保子特征的键是唯一的，并且不会覆盖主特征
                if (mainFeature === 'ip' && (subFeature === 'asn' || subFeature === 'cc')) {
                    features[subFeature] = {};
                } else if (mainFeature === 'ua' && (subFeature === 'bv' || subFeature === 'osv' || subFeature === 'df')) {
                    features[subFeature] = {};
                } else if (mainFeature === 'rtt') {
                    features[subFeature] = {};
                }
            }
        }

        return features;
    }

    // 辅助方法：初始化总计数结构 - 确保包含所有主特征和子特征
    _initTotalStats() {
        const totals = {};

        // 为每个主特征初始化计数为0
        for (const mainFeature of Object.keys(config.coefficients)) {
            totals[mainFeature] = 0;

            // 为每个子特征也初始化计数为0
            for (const subFeature of Object.keys(config.coefficients[mainFeature])) {
                // 确保子特征的键是唯一的，并且不会覆盖主特征
                if (mainFeature === 'ip' && (subFeature === 'asn' || subFeature === 'cc')) {
                    totals[subFeature] = 0;
                } else if (mainFeature === 'ua' && (subFeature === 'bv' || subFeature === 'osv' || subFeature === 'df')) {
                    totals[subFeature] = 0;
                } else if (mainFeature === 'rtt') {
                    totals[subFeature] = 0;
                }
            }
        }

        return totals;
    }

    // 新增：更新用户历史记录方法
    /**
     * 更新用户历史记录
     * @param {string} userId - 用户ID
     * @param {Object} features - 当前登录特征
     * @param {Object} userHistory - 用户历史记录
     * @private
     */
    async _updateUserHistory(userId, features, userHistory) {
        try {
            // 增加登录次数
            userHistory.loginCount = (userHistory.loginCount || 0) + 1;

            // 更新IP特征
            if (features.ip) {
                const ipValue = features.ip.ip;
                if (ipValue) {
                    userHistory.features.ip[ipValue] = (userHistory.features.ip[ipValue] || 0) + 1;
                    userHistory.total.ip = (userHistory.total.ip || 0) + 1; // 累加总次数而不是计算不同值的数量
                }

                // 更新ASN特征
                const asnValue = features.ip.asn;
                if (asnValue) {
                    userHistory.features.asn[asnValue] = (userHistory.features.asn[asnValue] || 0) + 1;
                    userHistory.total.asn = (userHistory.total.asn || 0) + 1; // 累加ASN总次数
                }

                // 更新国家代码特征
                const ccValue = features.ip.cc;
                if (ccValue) {
                    userHistory.features.cc[ccValue] = (userHistory.features.cc[ccValue] || 0) + 1;
                    userHistory.total.cc = (userHistory.total.cc || 0) + 1; // 累加CC总次数
                }
            }

            // 更新UA特征
            if (features.ua) {
                const uaValue = features.ua.ua;
                if (uaValue) {
                    userHistory.features.ua[uaValue] = (userHistory.features.ua[uaValue] || 0) + 1;
                    userHistory.total.ua = (userHistory.total.ua || 0) + 1; // 累加总次数
                }

                // 更新浏览器版本特征
                const bvValue = features.ua.bv;
                if (bvValue) {
                    userHistory.features.bv[bvValue] = (userHistory.features.bv[bvValue] || 0) + 1;
                    userHistory.total.bv = (userHistory.total.bv || 0) + 1; // 累加总次数
                }

                // 更新操作系统版本特征
                const osvValue = features.ua.osv;
                if (osvValue) {
                    userHistory.features.osv[osvValue] = (userHistory.features.osv[osvValue] || 0) + 1;
                    userHistory.total.osv = (userHistory.total.osv || 0) + 1; // 累加总次数
                }

                // 更新设备类型特征
                const dfValue = features.ua.df;
                if (dfValue) {
                    userHistory.features.df[dfValue] = (userHistory.features.df[dfValue] || 0) + 1;
                    userHistory.total.df = (userHistory.total.df || 0) + 1; // 累加总次数
                }
            }


            // 新增：更新RTT特征
            if (features.rtt !== undefined) {
                // 格式化RTT值，确保存储格式一致
                const rttValue = parseFloat(features.rtt).toFixed(3);
                
                // 更新用户历史
                userHistory.features.rtt = userHistory.features.rtt || {};
                userHistory.features.rtt[rttValue] = (userHistory.features.rtt[rttValue] || 0) + 1;
                userHistory.total.rtt = (userHistory.total.rtt || 0) + 1;
                
                console.debug(`[用户历史] 更新RTT特征: ${rttValue}`);
            }



            console.debug(`[用户历史] 更新成功: ${userId}`, {
                loginCount: userHistory.loginCount,
                ipCount: Object.keys(userHistory.features.ip).length,
                uaCount: Object.keys(userHistory.features.ua).length,
                asnCount: Object.keys(userHistory.features.asn).length, // 新增ASN计数
                ccCount: Object.keys(userHistory.features.cc).length,   // 新增CC计数
                bvCount: Object.keys(userHistory.features.bv).length,   // 新增BV计数
                osvCount: Object.keys(userHistory.features.osv).length, // 新增OSV计数
                dfCount: Object.keys(userHistory.features.df).length,   // 新增DF计数
                rttCount: Object.keys(userHistory.features.rtt).length // 新增RTT计数
            });
        } catch (error) {
            console.error(`[用户历史] 更新失败: ${userId}`, error);
        }
    }

    /**
     * 计算子特征的条件概率 - 参考Python中的p_k方法
     * @param {string} subFeature - 子特征名称
     * @param {string} value - 子特征值
     * @param {Object} userHistory - 用户历史记录
     * @param {boolean} smoothing - 是否使用平滑处理
     * @returns {number} - 条件概率
     */
    _calculateSubFeatureProbability(subFeature, value, userHistory, smoothing = true) {
        // 获取子特征在历史中的出现次数
        const subFeatureCount = userHistory.features[subFeature]?.[value] || 0;
        const subFeatureTotal = userHistory.total[subFeature] || 0;

        // 计算子特征的条件概率 p(x|k)
        // 传入 subFeature 作为 featureType
        const pXGivenK = this._calculateProbability(subFeatureCount, subFeatureTotal, smoothing, subFeature);

        // 计算子特征的先验概率 p(k)
        const pK = this._calculatePriorProbability(subFeature, userHistory, smoothing);

        // 返回条件概率 p(x|k) * p(k)
        return pXGivenK * pK;
    }

    /**
     * 计算特征的概率 - 参考Python中的p方法
     * @param {number} count - 特征值出现次数
     * @param {number} total - 特征总出现次数
     * @param {boolean} smoothing - 是否使用平滑处理
     * @param {string} featureType - 特征类型，用于 _calculateUnseenFeatures
     * @returns {number} - 概率值
     */
    _calculateProbability(count, total, smoothing = true, featureType = 'unknown') {
        if (total === 0) return smoothing ? 0.5 : 0.0;

        // 计算未见特征数量用于平滑处理
        // 这里的 featureType 需要从外部传入，或者根据上下文推断
        // 暂时假设 featureType 为 'unknown' 或不传，让 _calculateUnseenFeatures 内部处理
        const unseenFeatures = this._calculateUnseenFeatures(total, smoothing, featureType);
        return (count + unseenFeatures) / (total + unseenFeatures);
    }

    /**
     * 计算特征的先验概率 - 简化版
     * @param {string} feature - 特征名称
     * @param {Object} history - 历史记录
     * @param {boolean} smoothing - 是否使用平滑处理
     * @returns {number} - 先验概率
     */
    _calculatePriorProbability(feature, history, smoothing = true) {
        // 简化实现，返回该特征在历史中的占比
        const featureTotal = history.total[feature] || 0;
        const loginCount = history.loginCount || 1;

        if (featureTotal > 0) {
            return featureTotal / loginCount;
        } else {
            // 对于 rtt 特征，如果 total 为 0，则返回一个默认值，避免除以零
            if (feature === 'rtt') {
                return smoothing ? 0.01 : 0.0; // 假设 rtt 默认概率较低
            }
            return smoothing ? 0.5 : 0.0;
        }
    }

    /**
     * 计算未见特征数量 - 简化版M_hk方法
     * @param {number} total - 特征总数
     * @param {boolean} smoothing - 是否使用平滑处理
     * @returns {number} - 未见特征估计数量
     */
    _calculateUnseenFeatures(total, smoothing, featureType) {
        // 简化处理，直接返回一个基于总数的估计值
        // 实际应用中，这里需要更复杂的统计模型来估计未见特征数量
        // 例如，可以根据历史数据中不同特征值的增长趋势来预测
        // 或者使用更高级的平滑技术，如Good-Turing估计

        // 临时简化：如果 total 为 0，则未见特征为 1，否则为总数的某个比例
        if (total === 0) {
            return 1; // 至少有一个未见特征
        }

        // 可以根据 featureType 进行更细致的调整
        let factor = config.unseenFeatureFactor; // 默认系数
        if (featureType === 'rtt') {
            factor = 0.05; // RTT可能变化较小，系数可以小一点
        }

        return Math.max(1, Math.floor(total * factor));
    }

    /**
     * 计算用户风险评分（异步方法）
     * @param {string} userId - 用户ID
     * @param {Object} features - 登录特征对象
     * @returns {Promise<Object>} 风险评估结果
     */
    async calculate(userId, features) {
        // 配置项空值校验
        if (!config.coefficients || typeof config.coefficients !== 'object' || Object.keys(config.coefficients).length === 0) {
            throw new Error('风险系数配置异常: config.coefficients未正确定义');
        }

        console.debug(`[风险引擎] 开始计算用户 ${userId} 的风险评分，输入特征:`, JSON.stringify(features, null, 2));

        // 新增动态系数遍历验证
        console.debug('[风险引擎] 动态系数配置条目:', JSON.stringify(Object.entries(config.dynamicCoefficients), null, 2));

        const { globalHistory, userHistory } = await this._getHistories(userId);
        const p_L = 1 / (1 + Math.exp(-0.1 * userHistory.loginCount));

        console.debug('[风险引擎] 获取历史数据完成', {
            globalLoginCount: globalHistory.loginCount,
            userLoginCount: userHistory.loginCount,
            p_L: p_L
        });

        let riskScore = 0.0; // 初始分数为0，因为我们使用累加而不是连乘
        const dynamicCoeffEntries = Object.entries(config.dynamicCoefficients);
        const totalCoefficients = dynamicCoeffEntries.reduce((sum, [_, coeffConfig]) => sum + coeffConfig.coefficient, 0);

        console.debug('[风险引擎] 开始遍历动态系数，总计:', dynamicCoeffEntries.length, '个', { totalCoefficients });

        for (const [featureName, coeffConfig] of dynamicCoeffEntries) {
            console.debug('[风险引擎] 处理特征:', featureName);

            const featureValue = this._parseFeature(featureName, features);
            console.debug('[特征解析]', { feature: featureName, value: featureValue });

            // 获取正确的特征值用于查询历史记录
            let lookupValue;
            if (featureName === 'ip') {
                lookupValue = featureValue.ip; // 使用IP地址字符串
            } else if (featureName === 'ua') {
                lookupValue = featureValue.ua; // 使用浏览器名称字符串
            } else if (featureName === 'rtt') {
                // 对RTT进行格式化，确保与历史记录中的格式一致
                lookupValue = featureValue.toFixed(3);
            } else {
                lookupValue = featureValue;
            }

            const p_A = this._calcAttackerProbability(featureName, featureValue);
            const userHistoryCount = userHistory.features[featureName]?.[lookupValue] || 0;
            const p_x_L = this._smooth(userHistoryCount, userHistory.total[featureName]);
            const p_x = this._calcGlobalProb(featureName, featureValue, globalHistory);

            console.debug(`[风险引擎] 特征 ${featureName} 概率计算结果:`, {
                p_A: p_A, // 攻击者概率
                p_x_L: p_x_L, // 用户本地概率
                p_x: p_x, // 全局概率
                lookupValue: lookupValue, // 用于查询的特征值
                userHistoryCount: userHistoryCount, // 用户历史中该特征值的出现次数
                userHistoryTotal: userHistory.total[featureName] || 0, // 用户历史中该特征的总次数
                globalHistoryCount: globalHistory.globalStats.featureStats[featureName]?.[lookupValue] || 0, // 全局历史中该特征值的出现次数
                globalHistoryTotal: globalHistory.globalStats.totalStats[featureName] || 0 // 全局历史中该特征的总次数
            });

            // 使用贝叶斯公式计算特征风险: p(A|x) = (p(x|A) * p(A)) / (p(x|A) * p(A) + p(x|L) * p(L))
            // 这里 p(x|A) 近似为 p_x，p(x|L) 近似为 p_x_L
            let featureRisk;
            if (p_x_L === 0 || p_x === 0) {
                console.warn(`[风险引擎] p_x_L 或 p_x 为零，特征 ${featureName} 的风险分数计算使用备选方案。`);
                // 当概率为0时，使用攻击者概率作为基础风险值
                featureRisk = p_A;
            } else {
                featureRisk = (p_x * p_A) / (p_x * p_A + p_x_L * p_L);
            }
            
            // 应用特征权重
            const weightedRisk = featureRisk * coeffConfig.coefficient;
            riskScore += weightedRisk; // 累加而不是相乘，避免连乘导致分数过小

            console.debug(`[风险引擎] 特征 ${featureName} 风险计算:`, { 
                featureRisk: featureRisk,
                coefficient: coeffConfig.coefficient,
                weightedRisk: weightedRisk,
                currentRiskScore: riskScore
            });
        }

        console.debug('[风险引擎] 所有特征计算完成', { rawScore: riskScore, totalCoefficients });

        // 确保 riskScore 是一个有效数字，避免 NaN 传播
        const safeRiskScore = isNaN(riskScore) ? 0 : riskScore;
        
        // 归一化风险分数，除以总系数权重
        const normalizedScore = safeRiskScore / totalCoefficients;
        
        // 使用 Sigmoid 函数将分数映射到 [0, 1] 范围，并调整曲线形状
        // 参数 k 控制曲线的陡峭程度，较大的 k 使中等风险更明显区分
        const k = 4.0;
        const finalScore = 1 / (1 + Math.exp(-k * (normalizedScore - 0.5)));
        
        console.debug('[风险引擎] 最终风险分数计算', { 
            safeRiskScore, 
            normalizedScore, 
            finalScore 
        });

        const action = finalScore > config.risk.rejectThreshold ? 'REJECT' :
                       finalScore > config.risk.requestThreshold ? 'CHALLENGE' : 'ALLOW';

        console.debug('[风险引擎] 风险评估结果', { action: action });

        return {
            score: finalScore,
            action: action
        };
    }

    _calcAttackerProbability(feature, value) {
        // 实现基于特征的概率计算逻辑（参考core.py的系数模型）
        switch(feature) {
            case 'ip':
                return this._calcIPRisk(value);
            case 'ua':
                return this._calcUARisk(value);
            case 'rtt':
                // 使用更平滑的概率分布计算RTT风险
                // RTT值越大，风险越高，使用sigmoid函数映射到[0.1, 0.9]范围
                if (typeof value !== 'number') {
                    console.warn('[风险引擎] RTT值不是数字:', value);
                    return 0.5; // 默认中等风险
                }
                
                // 对RTT进行归一化处理
                // 假设正常RTT范围在0-500ms，超过1000ms视为高风险
                const normalizedRTT = Math.min(value, 2000) / 1000; // 限制最大值为2000ms
                
                // 使用sigmoid函数将归一化RTT映射到[0.1, 0.9]范围
                // 公式: 0.1 + 0.8 / (1 + Math.exp(-5 * (x - 0.5)))
                // 其中x是归一化后的RTT值，5控制曲线陡峭程度，0.5是中点
                const riskProb = 0.1 + 0.8 / (1 + Math.exp(-5 * (normalizedRTT - 0.5)));
                
                console.debug('[风险引擎] RTT风险计算:', { 
                    rtt: value, 
                    normalizedRTT, 
                    riskProb 
                });
                
                return riskProb;
            default:{
                return 0.5; // 默认中等风险
            }
        }
    }

    /**
     * 计算IP风险概率
     * @param {Object} ipData - IP数据对象 {ip, asn, cc}
     * @returns {number} 风险概率
     */
    _calcIPRisk(ipData) {
        if (!ipData) {
            console.warn('[风险引擎] IP数据为空');
            return 0.5; // 默认中等风险
        }
        
        let riskLevel = 0.3; // 默认基础风险
        let riskFactors = [];
        
        // 本地IP视为低风险
        if (ipData.ip === '::1' || ipData.ip === '127.0.0.1' || ipData.ip.startsWith('192.168.') || ipData.ip.startsWith('10.')) {
            riskLevel = 0.05;
            riskFactors.push('本地IP');
        }
        // 高风险ASN
        else if (this.maliciousNetworks && this.maliciousNetworks.includes(ipData.asn)) {
            riskLevel = 0.8;
            riskFactors.push('高风险ASN');
        }
        // 高风险国家
        else if (config.maliciousCountries && config.maliciousCountries.includes(ipData.cc)) {
            riskLevel = 0.7;
            riskFactors.push('高风险国家');
        }
        // 未知ASN
        else if (!ipData.asn || ipData.asn === 'Unknown') {
            riskLevel = 0.5;
            riskFactors.push('未知ASN');
        }
        // 未知国家
        else if (!ipData.cc || ipData.cc === 'XX') {
            riskLevel = 0.5;
            riskFactors.push('未知国家');
        }
        
        console.debug('[风险引擎] IP风险计算:', { 
            ip: ipData.ip, 
            asn: ipData.asn, 
            cc: ipData.cc, 
            riskLevel,
            riskFactors
        });
        
        return riskLevel;
    }

    /**
     * 计算UA风险概率
     * @param {Object} uaData - UA数据对象 {ua, bv, osv, df}
     * @returns {number} 风险概率
     */
    _calcUARisk(uaData) {
        if (!uaData) {
            console.warn('[风险引擎] UA数据为空');
            return 0.5; // 默认中等风险
        }
        
        let riskLevel = 0.2; // 默认基础风险
        let riskFactors = [];
        
        // 检查浏览器类型
        const browserName = uaData.ua || 'Unknown';
        const browserVersion = uaData.bv || '0.0.0';
        const osVersion = uaData.osv || 'Unknown';
        const deviceType = uaData.df || 'unknown';
        
        // 解析浏览器版本为数字
        const versionNumber = parseInt(browserVersion.split('.')[0]) || 0;
        
        // 检查浏览器版本是否过低
        const minVersion = config.minBrowserVersion[browserName] || 70;
        
        // 未知浏览器风险较高
        if (browserName === 'Unknown') {
            riskLevel = 0.7;
            riskFactors.push('未知浏览器');
        }
        // 版本过低的浏览器风险较高
        else if (versionNumber < minVersion) {
            // 版本越低，风险越高
            const versionGap = minVersion - versionNumber;
            riskLevel = Math.min(0.9, 0.5 + versionGap * 0.05); // 最高风险0.9
            riskFactors.push(`浏览器版本过低(${versionNumber}<${minVersion})`);
        }
        // 常见浏览器风险较低
        else if (['Chrome', 'Firefox', 'Safari', 'Edge'].includes(browserName)) {
            riskLevel = 0.1;
            riskFactors.push('常见浏览器');
        }
        
        // 设备类型风险调整
        if (deviceType !== 'desktop' && deviceType !== 'unknown') {
            // 移动设备略微增加风险
            riskLevel += 0.1;
            riskFactors.push('移动设备');
        }
        
        // 未知操作系统版本略微增加风险
        if (osVersion === 'Unknown') {
            riskLevel += 0.1;
            riskFactors.push('未知操作系统');
        }
        
        // 确保风险值在[0.1, 0.9]范围内
        riskLevel = Math.max(0.1, Math.min(0.9, riskLevel));
        
        console.debug('[风险引擎] UA风险计算:', { 
            browser: browserName, 
            version: browserVersion, 
            os: osVersion, 
            device: deviceType,
            riskLevel,
            riskFactors
        });
        
        return riskLevel;
    }
}

module.exports = RiskEngine;






    