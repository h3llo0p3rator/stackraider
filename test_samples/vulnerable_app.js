/**
 * SAMPLE VULNERABLE CODE FOR TESTING
 * This file contains intentional vulnerabilities for scanner verification.
 * DO NOT USE IN PRODUCTION!
 */

const express = require('express');
const { exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const mongoose = require('mongoose');

// ============================================
// AUTH-005/008: Backdoor URL Parameter
// ============================================
import { getConfig } from '.';

const allowedList = getConfig('siteAdminEmails');
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);

const isAdminUser = (userEmail) => {
    let isAdmin = false;
    // VULNERABLE: Backdoor parameter 'kingcharles' enables admin check
    // VULNERABLE: .includes() allows partial email matching
    if (allowedList && allowedList.length > 0 && userEmail && urlParams.has('kingcharles')) {
        isAdmin = allowedList.some((email) => userEmail.toLowerCase().includes(email));
    }
    return isAdmin;
};

// ============================================
// AUTH-006: Insecure String Matching
// ============================================
const trustedDomains = ['@company.com', '@admin.company.com'];

function isFromTrustedDomain(email) {
    // VULNERABLE: uses includes instead of exact match
    return trustedDomains.some(domain => email.includes(domain));
}

// ============================================
// AUTH-007: Client-Side Authorization
// ============================================
const checkUserPermissions = () => {
    // VULNERABLE: Authorization from localStorage
    const userRole = localStorage.getItem('userRole');
    const isAdmin = sessionStorage.getItem('isAdmin') === 'true';
    const hasAccess = JSON.parse(localStorage.getItem('permissions') || '{}').admin;
    
    return userRole === 'admin' || isAdmin || hasAccess;
};

// ============================================
// AUTH-010: Mass Assignment Risk
// ============================================
function getUserFromToken(token) {
    const user = jwt.decode(token);
    // VULNERABLE: checking user.isAdmin from JWT claims that might be controllable
    if (user.isAdmin || user.role === 'administrator') {
        return { ...user, privileges: 'full' };
    }
    return user;
}

const app = express();
app.use(express.json());

// ============================================
// CMD-001: Command Injection via exec
// ============================================
app.get('/convert', (req, res) => {
    const filename = req.query.file;
    // VULNERABLE: User input directly in command
    exec(`convert ${filename} output.png`, (err, stdout) => {
        res.send(stdout);
    });
});

// ============================================
// CMD-003: eval() with user input
// ============================================
app.post('/calculate', (req, res) => {
    const expression = req.body.expr;
    // VULNERABLE: eval with user input
    const result = eval(expression);
    res.json({ result });
});

// ============================================
// SQL-001: SQL Injection
// ============================================
app.get('/users', async (req, res) => {
    const userId = req.query.id;
    // VULNERABLE: String concatenation in SQL
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    const results = await db.query(query);
    res.json(results);
});

// ============================================
// NOSQL-001: NoSQL Injection
// ============================================
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    // VULNERABLE: Direct object in query allows operator injection
    const user = await User.findOne({
        username: username,
        password: password,
        $where: "this.active == true"
    });
    res.json({ user });
});

// ============================================
// XSS-001: DOM XSS via innerHTML
// ============================================
function displayMessage(userInput) {
    // VULNERABLE: User input in innerHTML
    document.getElementById('output').innerHTML = userInput;
}

// ============================================
// XSS-003: dangerouslySetInnerHTML
// ============================================
function UserContent({ content }) {
    // VULNERABLE: Unsanitized content
    return <div dangerouslySetInnerHTML={{__html: content}} />;
}

// ============================================
// PATH-001: Path Traversal
// ============================================
app.get('/download', (req, res) => {
    const filename = req.query.name;
    // VULNERABLE: Path traversal possible
    const filePath = '/uploads/' + filename;
    const content = fs.readFileSync(filePath);
    res.send(content);
});

// ============================================
// SSRF-001: Server-Side Request Forgery
// ============================================
app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    // VULNERABLE: User-controlled URL
    const response = await axios.get(url);
    res.json(response.data);
});

// ============================================
// AUTH-001: Hardcoded JWT Secret
// ============================================
const JWT_SECRET = 'supersecretkey123';

app.post('/auth', (req, res) => {
    const token = jwt.sign({ user: req.body.user }, 'secret123');
    res.json({ token });
});

// ============================================
// AUTH-003: Hardcoded Credentials
// ============================================
const dbConfig = {
    host: 'localhost',
    user: 'admin',
    password: 'admin123secure',
    database: 'myapp'
};

const API_KEY = '<STRIPE_API_KEY_PLACEHOLDER>';

// ============================================
// INFO-001: AWS Access Key
// ============================================
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

// ============================================
// INFO-004: Database Connection String
// ============================================
const mongoUri = 'mongodb://dbuser:dbpass123@production.mongodb.net:27017/mydb';
const redisUrl = 'redis://user:password123@redis.example.com:6379';

// ============================================
// CONFIG-001: CORS Allow All
// ============================================
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    next();
});

// ============================================
// CONFIG-003: Insecure Cookie
// ============================================
app.use(session({
    cookie: {
        httpOnly: false,
        secure: false,
        sameSite: 'none'
    }
}));

// ============================================
// CONFIG-004: TLS Verification Disabled
// ============================================
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const httpsAgent = new https.Agent({
    rejectUnauthorized: false
});

// ============================================
// RAND-001: Weak Randomness
// ============================================
function generateToken() {
    // VULNERABLE: Math.random is predictable
    return Math.random().toString(36).substring(2);
}

// ============================================
// PROTO-001: Prototype Pollution
// ============================================
app.post('/settings', (req, res) => {
    const userSettings = req.body;
    // VULNERABLE: merge with user input
    Object.assign(config, userSettings);
    res.json(config);
});

// ============================================
// REDIRECT-001: Open Redirect
// ============================================
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    // VULNERABLE: Open redirect
    res.redirect(url);
});

// ============================================
// MASS-001: Mass Assignment
// ============================================
app.post('/profile', async (req, res) => {
    // VULNERABLE: Entire body passed to update
    await User.findByIdAndUpdate(req.user.id, req.body);
    res.json({ success: true });
});

// ============================================
// CRYPTO-001: Weak Hash
// ============================================
const crypto = require('crypto');

function hashPassword(password) {
    // VULNERABLE: MD5 is weak
    return crypto.createHash('md5').update(password).digest('hex');
}

// ============================================
// LOG-001: Sensitive Data in Logs
// ============================================
app.post('/login-log', (req, res) => {
    const { username, password } = req.body;
    // VULNERABLE: Logging password
    console.log(`Login attempt: ${username} with password ${password}`);
    res.json({ success: true });
});

// ============================================
// DOS-001: ReDoS
// ============================================
app.get('/search', (req, res) => {
    const pattern = req.query.pattern;
    // VULNERABLE: User-controlled regex
    const regex = new RegExp(pattern);
    const matches = data.match(regex);
    res.json(matches);
});

module.exports = app;

