// 🚨 DEMO FILE: Intentionally vulnerable for security analysis demonstration
// This file contains multiple critical security vulnerabilities and poor practices

const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const lodash = require('lodash');
const moment = require('moment');
const validator = require('validator');
const multer = require('multer');
const helmet = require('helmet');
const cors = require('cors');

const app = express();

// 🚨 CRITICAL: Hardcoded database credentials in source code
const dbConfig = {
  host: 'localhost',
  user: 'admin',
  password: 'super_secret_password_123!',
  database: 'users_db'
};

// 🚨 CRITICAL: Hardcoded JWT secret
const JWT_SECRET = 'my_super_secret_jwt_key_that_is_way_too_short_and_guessable';

// 🚨 CRITICAL: No input validation or sanitization
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // 🚨 CRITICAL: SQL injection vulnerability
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  const connection = mysql.createConnection(dbConfig);
  connection.query(query, (error, results) => {
    if (error) {
      console.log('Database error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    if (results.length > 0) {
      // 🚨 CRITICAL: Weak password hashing (should use bcrypt with proper salt rounds)
      const hashedPassword = require('crypto').createHash('md5').update(password).digest('hex');
      
      if (hashedPassword === results[0].password) {
        // 🚨 CRITICAL: JWT token with no expiration
        const token = jwt.sign({ userId: results[0].id }, JWT_SECRET);
        res.json({ token, user: results[0] });
      } else {
        res.status(401).json({ error: 'Invalid credentials' });
      }
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

// 🚨 CRITICAL: No authentication middleware
app.get('/api/admin/users', (req, res) => {
  // 🚨 CRITICAL: Exposing all user data without authentication
  const query = 'SELECT id, username, email, password FROM users';
  
  const connection = mysql.createConnection(dbConfig);
  connection.query(query, (error, results) => {
    if (error) {
      console.log('Database error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    // 🚨 CRITICAL: Exposing sensitive data including hashed passwords
    res.json({ users: results });
  });
});

// 🚨 CRITICAL: File upload without validation
app.post('/api/upload', multer().single('file'), (req, res) => {
  const file = req.file;
  
  // 🚨 CRITICAL: No file type validation - allows any file upload
  // 🚨 CRITICAL: No file size limits
  // 🚨 CRITICAL: No virus scanning
  
  if (file) {
    // 🚨 CRITICAL: Storing files in web-accessible directory
    const fs = require('fs');
    const path = require('path');
    const uploadPath = path.join(__dirname, 'public', 'uploads', file.originalname);
    
    fs.writeFileSync(uploadPath, file.buffer);
    res.json({ message: 'File uploaded successfully', path: uploadPath });
  } else {
    res.status(400).json({ error: 'No file provided' });
  }
});

// 🚨 CRITICAL: Command injection vulnerability
app.post('/api/backup', (req, res) => {
  const { database } = req.body;
  
  // 🚨 CRITICAL: Command injection - user input directly in shell command
  const command = `mysqldump -u admin -p${dbConfig.password} ${database} > backup.sql`;
  
  const { exec } = require('child_process');
  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.log('Backup error:', error);
      return res.status(500).json({ error: 'Backup failed' });
    }
    res.json({ message: 'Backup completed successfully' });
  });
});

// 🚨 CRITICAL: XSS vulnerability
app.post('/api/comment', (req, res) => {
  const { comment } = req.body;
  
  // 🚨 CRITICAL: No input sanitization - allows XSS attacks
  const query = `INSERT INTO comments (content) VALUES ('${comment}')`;
  
  const connection = mysql.createConnection(dbConfig);
  connection.query(query, (error, results) => {
    if (error) {
      console.log('Database error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    res.json({ message: 'Comment added successfully' });
  });
});

// 🚨 CRITICAL: SSRF vulnerability
app.get('/api/proxy', async (req, res) => {
  const { url } = req.query;
  
  // 🚨 CRITICAL: No URL validation - allows SSRF attacks
  try {
    const response = await axios.get(url);
    res.json({ data: response.data });
  } catch (error) {
    res.status(500).json({ error: 'Proxy request failed' });
  }
});

// 🚨 CRITICAL: Insecure random number generation
app.get('/api/token', (req, res) => {
  // 🚨 CRITICAL: Using Math.random() for security tokens
  const token = Math.random().toString(36).substring(2);
  res.json({ token });
});

// 🚨 CRITICAL: Information disclosure
app.use((error, req, res, next) => {
  // 🚨 CRITICAL: Exposing internal error details
  console.log('Error details:', error);
  res.status(500).json({ 
    error: 'Internal server error',
    details: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString()
  });
});

// 🚨 CRITICAL: No rate limiting
// 🚨 CRITICAL: No CORS configuration
// 🚨 CRITICAL: No security headers

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚨 VULNERABLE SERVER RUNNING ON PORT ${PORT}`);
  console.log('🚨 This server is intentionally insecure for demonstration purposes');
  console.log('🚨 DO NOT USE IN PRODUCTION!');
});

// 🚨 CRITICAL: Outdated and vulnerable dependencies
// - express: 4.17.1 (has known vulnerabilities)
// - mysql: 2.18.1 (deprecated, use mysql2)
// - bcrypt: 3.0.6 (outdated)
// - jsonwebtoken: 8.5.1 (has known vulnerabilities)
// - axios: 0.21.1 (has known vulnerabilities)
// - lodash: 4.17.15 (has known vulnerabilities)
// - moment: 2.29.1 (deprecated, use date-fns)
// - validator: 13.6.0 (has known vulnerabilities)
// - multer: 1.4.2 (has known vulnerabilities)
// - helmet: 4.6.0 (outdated)

module.exports = app;
