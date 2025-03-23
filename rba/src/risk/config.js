require('dotenv').config();

module.exports = {
    coefficients: {
        ip: {
            ip: 0.6,
            asn: 0.3,
            cc: 0.1
        },
        ua: {
            ua: 0.538,
            bv: 0.268,
            osv: 0.188,
            df: 0.005
        },
        rtt: {
            rtt: 1.0
        }
    },



    // 删除重复的risk配置，只保留一个
    risk: {
        rejectThreshold: 0.7,   // 拒绝阈值
        requestThreshold: 0.4   // 挑战阈值
    },
    smoothingAlpha: 1,       // 平滑系数
    maliciousCountries: ['XX', 'XY'], // 高风险国家代码
    minBrowserVersion: {     // 浏览器最低版本
      Chrome: 85,
      Firefox: 78
    },

    // 使用环境变量与默认值结合
    maxHistory: process.env.RISK_MAX_HISTORY || 50,

    maxmind: {
        asnPath: process.env.GEOIP_ASN_DATABASE || './geoip/GeoLite2-ASN.mmdb',
        countryPath: process.env.GEOIP_COUNTRY_DATABASE || './geoip/GeoLite2-Country.mmdb'
    },

    database: {
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD, // 强制要求通过环境变量设置
        database: process.env.DB_NAME,
        port: process.env.DB_PORT || 3306,
        waitForConnections: true,
        connectionLimit: 10,
        ssl: process.env.NODE_ENV === 'production' ? {
            rejectUnauthorized: true,
            ca: process.env.DB_SSL_CA // 生产环境建议添加CA证书
        } : null,
        timezone: '+00:00' // 建议明确设置时区
    },
    risk:{
        rejectThreshold:2.0
    }
};