const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 10;

// 添加信任代理设置
app.set('trust proxy', true);

// 静态文件服务
app.use(express.static(path.join(__dirname, 'public')));

// 解析 JSON 和 Cookie
app.use(express.json());
app.use(cookieParser());

// 用户数据存储路径
const USERS_FILE = path.join(__dirname, 'users.json');
const ADMIN_USERNAME = 'admin';

// 导入中间件
const { middleware: historyStoreMiddleware } = require('./middlewares/history-store');
const riskAssessmentMiddleware = require('./middlewares/risk-assessment');
const authMiddleware=require('./middlewares/authMiddleware')

// 中间件：管理员身份验证
const adminAuth = (req, res, next) => {
    try {
        const sessionId = req.cookies.sessionId;
        const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        const admin = users.find(u => u.username === ADMIN_USERNAME);

        if (sessionId && admin.sessionId === sessionId) {
            return next();
        }

        res.redirect('/admin-login');
    } catch (error) {
        console.error('管理员验证失败:', error);
        res.status(500).send('服务器内部错误');
    }
};

// 管理员登录处理
app.post('/admin/login', (req, res) => {
    try {
        const { username, password } = req.body;
        const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        const admin = users.find(u => u.username === username);

        if (!admin) {
            return res.status(401).send('无效的管理员凭证');
        }

        const passwordMatch = bcrypt.compareSync(password, admin.password);
        if (!passwordMatch) {
            return res.status(401).send('无效的管理员凭证');
        }

        const sessionId = require('crypto').randomBytes(16).toString('hex');
        admin.sessionId = sessionId;
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');

        res.cookie('sessionId', sessionId, {
            httpOnly: true,
            maxAge: 3600000
        });

        res.sendStatus(200);
    } catch (error) {
        console.error('管理员登录错误:', error);
        res.status(500).send('服务器内部错误');
    }
});

// 中间件：记录客户端信息
app.use((req, res, next) => {
    const clientInfo = {
        ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
        userAgent: req.body.user_agent || req.headers['user-agent'] || 'unknown',  // 优先使用前端提交的UA
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url
    };
    req.clientInfo = clientInfo; // 将客户端信息挂载到请求对象
    console.log('Client Info:', clientInfo);
    next();
});

// 初始化用户文件
function initUsersFile() {
    try {
        fs.accessSync(USERS_FILE);
    } catch (error) {
        fs.writeFileSync(USERS_FILE, '[]', { encoding: 'utf8' });
    }
}

// 初始化管理员账号
function initAdminUser() {
    try {
        const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        const adminExists = users.some(u => u.username === ADMIN_USERNAME);

        if (!adminExists) {
            const hashedPassword = bcrypt.hashSync('admin123', 10);
            const adminUser = {
                id: 'admin',
                username: ADMIN_USERNAME,
                password: hashedPassword,
                isAdmin: true,
                createdAt: new Date().toISOString(),
                lastLogin: null,
                loginHistory: []
            };
            users.push(adminUser);
            fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
            console.log('管理员账号已创建');
        }
    } catch (error) {
        console.error('初始化管理员账号失败:', error);
    }
}

initUsersFile();
initAdminUser();

// 路由配置
app.get('/', (req, res) => res.redirect('/login'));
app.get('/login', 
    //authMiddleware,  
    //historyStoreMiddleware,  // 中间件1：历史记录
    //riskAssessmentMiddleware, // 中间件2：风险评估
    (req, res) => {
      res.sendFile(path.join(__dirname, 'public/login.html'));
    }
  );
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public/register.html')));
app.get('/admin', adminAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/admin.html')));
app.get('/admin-login', (req, res) => res.sendFile(path.join(__dirname, 'public/admin-login.html')));

// 用户注册处理
app.post('/register', (req, res) => {
    try {
        const { username, email, password } = req.body;
        const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));

        if (users.some(u => u.username === username)) {
            return res.status(400).json({ message: '用户名已存在' });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        const newUser = {
            id: Date.now().toString(),
            username,
            email,
            password: hashedPassword,
            createdAt: new Date().toISOString(),
            lastLogin: null,
            loginHistory: []
        };

        users.push(newUser);
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
        res.status(201).json({ message: '用户注册成功' });
    } catch (error) {
        console.error('注册错误:', error);
        res.status(500).json({ message: '服务器内部错误' });
    }
});


// 添加 2FA 页面路由
app.get('/verify-2fa', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/verify-2fa.html'));
  });



  app.post('/verify-2fa', (req, res) => {
    const { code } = req.body;
    // 验证逻辑：只要输入 123456 即可通过
    if (code === '123456') {
      res.json({ success: true });
    } else {
      res.status(401).json({ error: '验证码无效' });
    }
  });



app.post('/login', 
    express.json(),
    // // 客户端信息中间件应当最先执行
    // (req, res, next) => {
    //     const clientInfo = {
           
    //         ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
    //         userAgent: req.body.user_agent || req.headers['user-agent'] || 'unknown',  // 优先使用前端提交的UA
    //         timestamp: new Date().toISOString(),
    //         method: req.method,
    //         url: req.url
    //     };
    //     req.clientInfo = clientInfo;
    //     next();
    // },
    authMiddleware,
    historyStoreMiddleware,
    riskAssessmentMiddleware,
    async (req, res) => {
        if (!req.requires2FA) {
            // 中间件已处理登录记录，此处删除重复操作
            res.redirect('/success.html');
        } else {
            res.json({ requires2FA: true });
        }
    }
);

// 管理员API
app.get('/admin/users', adminAuth, (req, res) => {
    try {
        const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        const sanitizedUsers = users.map(user => ({
            id: user.id,
            username: user.username,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin,
            loginAttempts: (user.loginHistory || []).length
        }));
        res.json(sanitizedUsers);
    } catch (error) {
        console.error('获取用户列表失败:', error);
        res.status(500).json({ message: '服务器内部错误' });
    }
});

app.get('/admin/users/:id', adminAuth, (req, res) => {
    try {
        const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        const user = users.find(u => u.id === req.params.id);

        if (!user) {
            return res.status(404).json({ message: '用户不存在' });
        }

        res.json({
            loginHistory: (user.loginHistory || []).map(entry => ({
                timestamp: entry.timestamp,
                ip: entry.ip,
                userAgent: entry.userAgent,
                success: entry.success
            }))
        });
    } catch (error) {
        console.error('获取用户详情失败:', error);
        res.status(500).json({ message: '服务器内部错误' });
    }
});

app.delete('/admin/users/:id', adminAuth, (req, res) => {
    try {
        const userId = req.params.id;
        let users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        users = users.filter(user => user.id !== userId);
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
        res.json({ message: '用户删除成功' });
    } catch (error) {
        console.error('删除用户失败:', error);
        res.status(500).json({ message: '服务器内部错误' });
    }
});

// 启动服务器
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
