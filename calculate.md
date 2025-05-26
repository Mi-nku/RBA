```js
async calculate(userId, features) {
        // 配置项空值校验
        if (!config.coefficients || typeof config.coefficients !== 'object' || Object.keys(config.coefficients).length === 0) {
            throw new Error('风险系数配置异常: config.coefficients未正确定义');
        }
        console.debug('[配置检查] 当前coefficients结构:', JSON.stringify({
            coefficients: Object.keys(config.coefficients),
            subFeatures: Object.entries(config.coefficients).map(([k,v]) => ({
                main: k,
                weights: Object.keys(v)
            }))
        }, null, 2));
  
        const mainFeatures = Object.keys(config.coefficients).filter(k => 
            config.coefficients[k] && 
            typeof config.coefficients[k] === 'object' &&
            Object.keys(config.coefficients[k]).length > 0
        ) || [];
        console.debug('[配置详情] 当前有效系数配置:', JSON.stringify({
          totalFeatures: mainFeatures.length,
          features: mainFeatures.map(f => ({
            name: f,
            weights: Object.keys(config.coefficients[f] || {})
          }))
        }, null, 2));

        // 新增配置项详细验证
        for (const mainFeature of mainFeatures) {
            const subFeatures = config.coefficients[mainFeature];
            if (!subFeatures || typeof subFeatures !== 'object') {
                console.error(`[配置错误] 主特征${mainFeature}配置无效`);
                continue;
            }
            
            let geoData = null;
            let score = 1.0;
            const { globalHistory, userHistory } = await this._getHistories(userId);
            const p_L = 1 / (1 + Math.exp(-0.1 * userHistory.loginCount)); // 用户可信度概率

        // 贝叶斯风险计算
        let riskScore = 1.0;
  
        // 新增：检查 dynamicCoefficients 配置
        if (!config.dynamicCoefficients || typeof config.dynamicCoefficients !== 'object') {
            console.error('[配置错误] dynamicCoefficients 未正确定义');
            return {
                score: 1.0,  // 默认安全分数
                action: 'ALLOW'
            };
        }

        // 确保 dynamicCoefficients 有有效条目
        const dynamicCoeffs = Object.entries(config.dynamicCoefficients).filter(
            ([, coeffs]) => coeffs && typeof coeffs === 'object' && coeffs.weight !== undefined
        );
  
        if (dynamicCoeffs.length === 0) {
            console.error('[配置错误] dynamicCoefficients 没有有效配置');
            return {
                score: 1.0,
                action: 'ALLOW'
            };
        }

        let totalWeight = 0;

        for (const [feature, coeffs] of Object.entries(config.dynamicCoefficients)) {

            if (coeffs.weight < 0 || coeffs.weight > 1) {
                throw new Error(`动态系数权重 ${feature} 超出范围 [0, 1]`);
              }
            totalWeight += coeffs.weight;

            const featureValue = this._parseFeature(feature, features);
  
            // 计算p_A_given_xk（攻击者特征概率）
            const p_A = this._calcAttackerProbability(feature, featureValue);
  
            // 计算p_xk_given_L（合法用户特征概率）
            const p_x_L = this._smooth(
                userHistory.features[feature]?.[featureValue] || 0,
                userHistory.total[feature]
            );

            // 计算p_xk（全局特征概率）
            const p_x = this._smooth(
                globalHistory.features[feature]?.[featureValue] || 0,
                globalHistory.total[feature]
            );

            // 贝叶斯公式计算特征风险
            const featureRisk = (p_A * p_x) / (p_A * p_x + (1 - p_A) * p_x_L * p_L);
            riskScore *= 1 - (1 - featureRisk) * coeffs.weight;
        }

        // 动态阈值调整
        //const finalScore = Math.tanh(riskScore * config.riskThreshold.adjustmentFactor);
        const finalScore = 1 / (1 + Math.exp(-riskScore));
        const action = finalScore > config.risk.rejectThreshold ? 'REJECT' : 
          finalScore > config.risk.requestThreshold ? 'CHALLENGE' : 'ALLOW';
        console.debug('[最终风险评分]', { rawScore: riskScore, finalScore, action });
        return { 
          score: finalScore, 
          action: action 
        };
    }
    }
  
```
