const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`📥 ${req.method} ${req.path} - ${new Date().toLocaleTimeString()}`);
  if (req.body && Object.keys(req.body).length > 0) {
    // Don't log password in production
    const logBody = { ...req.body };
    if (logBody.password) {
      logBody.password = '***';
    }
    console.log('   Body:', JSON.stringify(logBody));
  }
  next();
});

// Database configuration
const dbConfig = {
  host: 'metro.proxy.rlwy.net',
  port: 16083,
  user: 'root',
  password: 'SEDdeAzxOuoemqszIwlYKgOUPhbZBPeJ',
  database: 'railway',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

// Create connection pool
const pool = mysql.createPool(dbConfig);

// Test database connection asynchronously
(async () => {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Successfully connected to MySQL database!');
    console.log('📊 Database:', dbConfig.database);
    console.log('🌐 Host:', dbConfig.host);
    console.log('🔌 Port:', dbConfig.port);
    console.log('👤 User:', dbConfig.user);
    connection.release(); // Release the connection back to the pool
  } catch (err) {
    console.error('❌ Database connection failed:', err.message);
    console.error('Error details:', err);
    console.error('⚠️  Server will continue to start, but database operations may fail.');
  }
})();

// Handle pool errors
pool.on('error', (err) => {
  console.error('❌ Database pool error:', err);
  if (err.code === 'PROTOCOL_CONNECTION_LOST') {
    console.error('Database connection was closed.');
  }
  if (err.code === 'ER_CON_COUNT_ERROR') {
    console.error('Database has too many connections.');
  }
  if (err.code === 'ECONNREFUSED') {
    console.error('Database connection was refused.');
  }
});

// JWT Secret (in production, use environment variable)
const JWT_SECRET = process.env.JWT_SECRET || 'kwai_portal_secret_key_2024';

// Email configuration with timeout and connection settings
// Using port 465 with SSL (more reliable than 587 with STARTTLS)
const emailTransporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 465,
  secure: true, // true for 465 (SSL), false for 587 (STARTTLS)
  auth: {
    user: process.env.EMAIL_USER || 'knewcodesolutions@gmail.com',
    pass: process.env.EMAIL_PASS || 'afeyyqhuewufgidr'
  },
  connectionTimeout: 30000, // 30 seconds (increased for production)
  greetingTimeout: 30000, // 30 seconds
  socketTimeout: 30000, // 30 seconds
  debug: process.env.NODE_ENV !== 'production', // Only debug in development
  logger: process.env.NODE_ENV !== 'production' // Only log in development
});

// Verify email transporter connection on startup (non-blocking)
emailTransporter.verify(function (error, success) {
  if (error) {
    console.error('❌ Email transporter verification failed:', error.message);
    console.error('❌ Error code:', error.code);
    console.error('❌ Error command:', error.command);
    console.error('📧 Email service may not work properly. Please check:');
    console.error('   1. Email credentials are correct');
    console.error('   2. Gmail app password is valid');
    console.error('   3. Server can reach smtp.gmail.com (port 587)');
    console.error('   4. Firewall allows outbound SMTP connections');
    console.error('   5. Gmail allows "Less secure app access" or app password is used');
  } else {
    console.log('✅ Email transporter verified successfully');
    console.log('📧 Email service is ready to send emails');
  }
});

// Store verification codes temporarily (in production, use Redis or database)
const verificationCodes = new Map(); // studentId -> { code, expiresAt, email }

// Helper function to execute queries
const query = async (sql, params = []) => {
  try {
    const [results] = await pool.execute(sql, params);
    return results;
  } catch (error) {
    console.error('Database error:', error);
    throw error;
  }
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.studentId = decoded.studentId;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Routes

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log(`🔐 Login attempt for: ${username}`);

    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username and password are required' });
    }

    // Check if username is email or student_id
    const isEmail = username.includes('@');
    const whereClause = isEmail 
      ? 'email = ?' 
      : 'student_id = ?';

    const [students] = await pool.execute(
      `SELECT * FROM students WHERE ${whereClause} ORDER BY year DESC`,
      [username]
    );

    if (students.length === 0) {
      return res.status(401).json({ success: false, error: 'Incorrect username or password' });
    }

    // Get all unique student_ids (in case email matches multiple records)
    const uniqueStudentIds = [...new Set(students.map(s => s.student_id))];
    
    // If email was used and matches multiple student_ids, that's an error
    if (isEmail && uniqueStudentIds.length > 1) {
      return res.status(401).json({ success: false, error: 'Multiple accounts found. Please use your Student ID to login.' });
    }

    const studentId = String(students[0].student_id); // Convert to string to ensure consistency
    
    // Get all records for this student_id to check password (password should be same across all years)
    const [allStudentRecords] = await pool.execute(
      'SELECT * FROM students WHERE student_id = ? ORDER BY year DESC',
      [studentId]
    );

    if (allStudentRecords.length === 0) {
      return res.status(401).json({ success: false, error: 'Incorrect username or password' });
    }

    // Check password against first record (password should be same for all years)
    const firstRecord = allStudentRecords[0];
    const dbPassword = firstRecord.password;

    // Check if password is empty in database (null, undefined, empty string, or only whitespace)
    // IMPORTANT: A password is considered empty ONLY if it's truly null/undefined/empty
    // If password exists (even if it's a hash), we must verify it with bcrypt
    const isPasswordEmpty = dbPassword === null || 
                           dbPassword === undefined || 
                           dbPassword === '' || 
                           (typeof dbPassword === 'string' && dbPassword.trim() === '');

    // Convert password and studentId to strings for comparison
    const passwordStr = String(password).trim();
    const studentIdStr = String(studentId).trim();

    console.log(`   Password field value: ${dbPassword === null ? 'NULL' : dbPassword === undefined ? 'UNDEFINED' : (dbPassword.length > 20 ? `"${dbPassword.substring(0, 20)}..." (hashed)` : `"${dbPassword}"`)}`);
    console.log(`   Password empty check: ${isPasswordEmpty}`);
    console.log(`   Provided password: "${passwordStr}"`);
    console.log(`   Student ID: "${studentIdStr}"`);

    // CRITICAL: Only allow password setup if password is TRULY empty
    // If password exists (even as a hash), we MUST verify it with bcrypt
    if (isPasswordEmpty) {
      // Password is empty - allow login with student_id as password for initial setup
      // Compare with trimmed string values to handle whitespace and type differences
      if (passwordStr === studentIdStr) {
        console.log(`   ✅ Password empty - allowing login with student_id, redirecting to password setup`);
        // Get available years
        const availableYears = [...new Set(allStudentRecords.map(s => s.year))];
        
        // Return flag to indicate password needs to be set
        return res.json({
          success: true,
          needsPasswordSetup: true,
          student: {
            id: firstRecord.id,
            studentId: firstRecord.student_id,
            firstName: firstRecord.first_name,
            lastName: firstRecord.last_name,
            middleInitial: firstRecord.middle_initial,
            email: firstRecord.email,
            gradeLevel: firstRecord.grade_level,
            lrn: firstRecord.lrn,
            guardianName: firstRecord.guardian,
            phoneNumber: firstRecord.phone_number,
            profilePhoto: firstRecord.image,
            year: firstRecord.year,
            semester: firstRecord.semester,
            availableYears: availableYears,
          }
        });
      } else {
        console.log(`   ❌ Password empty but provided password doesn't match student_id`);
        console.log(`   Expected: "${studentIdStr}", Got: "${passwordStr}"`);
        return res.status(401).json({ success: false, error: 'Incorrect password. Please use your Student ID as the password.' });
      }
    }

    // Password EXISTS in database - must verify with bcrypt
    // CRITICAL: Do NOT allow student_id as password if password is already set
    // Even if user enters student_id, we must verify against the stored hash
    let isValidPassword = false;
    
    try {
      // Try bcrypt comparison first (normal case)
      isValidPassword = await bcrypt.compare(passwordStr, dbPassword);
      
      // If bcrypt comparison fails, check if it's because password is not a valid hash
      // This handles edge cases where password might be stored in plain text (shouldn't happen)
      if (!isValidPassword && typeof dbPassword === 'string' && !dbPassword.startsWith('$2')) {
        // Password is not a bcrypt hash - compare directly (legacy support)
        // But still don't allow student_id as password if password exists
        console.log(`   ⚠️ Password is not a bcrypt hash - using direct comparison`);
        isValidPassword = (passwordStr === dbPassword.trim());
      }
    } catch (bcryptError) {
      console.error(`   ❌ Bcrypt comparison error:`, bcryptError);
      // If bcrypt fails, don't allow login
      isValidPassword = false;
    }
    
    console.log(`   Password exists - verification result: ${isValidPassword}`);

    if (!isValidPassword) {
      console.log(`   ❌ Password verification failed - password does not match`);
      console.log(`   ⚠️ Student has password set - cannot use student_id as password`);
      return res.status(401).json({ success: false, error: 'Incorrect password' });
    }
    
    console.log(`   ✅ Password verified successfully`);

    // Get available years for this student
    const availableYears = [...new Set(allStudentRecords.map(s => s.year))];

    // Generate JWT token
    const token = jwt.sign(
      { studentId: studentId, id: firstRecord.id },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log(`   ✅ Login successful for student: ${studentId}`);
    console.log(`   ✅ Login successful for student: ${studentId}`);
    res.json({
      success: true,
      token,
      needsPasswordSetup: false,
      student: {
        id: firstRecord.id,
        studentId: firstRecord.student_id,
        firstName: firstRecord.first_name,
        lastName: firstRecord.last_name,
        middleInitial: firstRecord.middle_initial,
        email: firstRecord.email,
        gradeLevel: firstRecord.grade_level,
        lrn: firstRecord.lrn,
        guardianName: firstRecord.guardian,
        phoneNumber: firstRecord.phone_number,
        profilePhoto: firstRecord.image,
        year: firstRecord.year,
        semester: firstRecord.semester,
        availableYears: availableYears,
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Send verification code endpoint
app.post('/api/auth/send-verification-code', async (req, res) => {
  try {
    const { studentId, email } = req.body;

    if (!studentId || !email) {
      return res.status(400).json({ success: false, error: 'Student ID and email are required' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, error: 'Invalid email format' });
    }

    // Check if email already exists for a different student_id
    const [existingEmailRecords] = await pool.execute(
      'SELECT DISTINCT student_id FROM students WHERE email = ? AND email IS NOT NULL AND email != ""',
      [email]
    );

    console.log(`🔍 Checking email ${email} for student_id ${studentId}`);
    console.log(`📋 Existing email records found:`, JSON.stringify(existingEmailRecords));

    if (existingEmailRecords.length > 0) {
      // Check if the email belongs to a different student_id
      // Convert both to strings and trim for comparison (student_id might be stored as VARCHAR or INT)
      const emailStudentIds = existingEmailRecords.map(r => {
        const id = r.student_id;
        return String(id).trim();
      });
      const currentStudentId = String(studentId).trim();
      
      console.log(`🔍 Comparing: currentStudentId="${currentStudentId}" with emailStudentIds=[${emailStudentIds.join(', ')}]`);
      
      // If email exists for a different student_id, reject
      if (!emailStudentIds.includes(currentStudentId)) {
        console.log(`❌ Email ${email} already exists for different student_id(s): ${emailStudentIds.join(', ')}`);
        console.log(`❌ Current student_id: ${currentStudentId} is NOT in the list`);
        return res.status(400).json({ 
          success: false, 
          error: 'This email is already registered to another account. Please use a different email address.' 
        });
      }
      
      // Email exists for the same student_id (multiple year records) - this is okay
      console.log(`✅ Email ${email} exists for same student_id ${studentId} - allowed (multiple year records)`);
    } else {
      console.log(`✅ Email ${email} is not yet registered - allowed`);
    }

    // Generate 6-digit verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 2 * 60 * 1000; // 2 minutes

    // Store verification code
    verificationCodes.set(studentId, {
      code: verificationCode,
      expiresAt,
      email
    });

    // Send email
    const mailOptions = {
      from: 'knewcodesolutions@gmail.com',
      to: email,
      subject: 'KWAI Portal - Verification Code',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #1E3A8A;">KWAI Portal Verification Code</h2>
          <p>Hello,</p>
          <p>Your verification code for creating your password is:</p>
          <div style="background-color: #F1F5F9; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px;">
            <h1 style="color: #1E3A8A; margin: 0; font-size: 32px; letter-spacing: 5px;">${verificationCode}</h1>
          </div>
          <p>This code will expire in 2 minutes.</p>
          <p>If you didn't request this code, please ignore this email.</p>
          <p style="color: #64748B; font-size: 12px; margin-top: 30px;">© Kabacan Wesleyan Academy, Inc.</p>
        </div>
      `
    };

    console.log(`📧 Attempting to send verification email to ${email} for student ${studentId}...`);
    console.log(`📧 Email details: From: ${mailOptions.from}, To: ${mailOptions.to}, Subject: ${mailOptions.subject}`);
    
    // Retry logic for email sending (3 attempts with exponential backoff)
    let emailResult;
    let lastError;
    const maxRetries = 3;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        console.log(`📧 Email send attempt ${attempt}/${maxRetries}...`);
        emailResult = await emailTransporter.sendMail(mailOptions);
        
        // Log successful email sending with details
        console.log('✅ EMAIL SENT SUCCESSFULLY!');
        console.log(`📧 Message ID: ${emailResult.messageId}`);
        console.log(`📧 Response: ${emailResult.response}`);
        console.log(`📧 Accepted recipients: ${JSON.stringify(emailResult.accepted)}`);
        console.log(`📧 Rejected recipients: ${JSON.stringify(emailResult.rejected)}`);
        console.log(`📧 Verification code sent to ${email} for student ${studentId}`);
        console.log(`📧 Verification code: ${verificationCode} (expires in 2 minutes)`);
        
        res.json({
          success: true,
          message: 'Verification code sent to your email'
        });
        return; // Success, exit the function
      } catch (error) {
        lastError = error;
        console.error(`❌ Email send attempt ${attempt}/${maxRetries} failed`);
        console.error(`❌ Error: ${error.message}`);
        console.error(`❌ Error code: ${error.code}`);
        
        // If not the last attempt, wait before retrying
        if (attempt < maxRetries) {
          const waitTime = Math.pow(2, attempt) * 1000; // Exponential backoff: 2s, 4s, 8s
          console.log(`⏳ Retrying in ${waitTime/1000} seconds...`);
          await new Promise(resolve => setTimeout(resolve, waitTime));
        }
      }
    }
    
    // If we get here, all retries failed
    throw lastError;
    
  } catch (error) {
    console.error('❌ EMAIL SENDING FAILED AFTER ALL RETRIES!');
    console.error('❌ Error details:', error);
    console.error('❌ Error message:', error.message);
    console.error('❌ Error code:', error.code);
    console.error('❌ Error command:', error.command);
    console.error('❌ Error response:', error.response);
    console.error('❌ Error responseCode:', error.responseCode);
    
    // Provide helpful error messages based on error type
    let errorMessage = 'Failed to send verification code';
    if (error.code === 'ETIMEDOUT' || error.code === 'ECONNREFUSED') {
      errorMessage = 'Email service is currently unavailable. Please try again later or contact support.';
      console.error('❌ Network/Connection issue detected');
    } else if (error.code === 'EAUTH') {
      errorMessage = 'Email authentication failed. Please contact support.';
      console.error('❌ Authentication issue - check email credentials');
    } else if (error.responseCode === 535) {
      errorMessage = 'Email authentication failed. Invalid credentials.';
      console.error('❌ Invalid email credentials');
    }
    
    console.error(`❌ Failed to send verification code to ${email} for student ${studentId}`);
    console.error('❌ Full error object:', JSON.stringify(error, Object.getOwnPropertyNames(error), 2));
    
    res.status(500).json({ 
      success: false, 
      error: errorMessage 
    });
  }
});

// Verify code and set password endpoint
app.post('/api/auth/set-password', async (req, res) => {
  try {
    const { studentId, newPassword, confirmPassword, email, verificationCode } = req.body;

    if (!studentId || !newPassword || !confirmPassword || !email || !verificationCode) {
      return res.status(400).json({ success: false, error: 'All fields are required' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, error: 'Invalid email format' });
    }

    // Check if email already exists for a different student_id
    const [existingEmailRecords] = await pool.execute(
      'SELECT DISTINCT student_id FROM students WHERE email = ? AND email IS NOT NULL AND email != ""',
      [email]
    );

    if (existingEmailRecords.length > 0) {
      // Check if the email belongs to a different student_id
      const emailStudentIds = existingEmailRecords.map(r => String(r.student_id));
      const currentStudentId = String(studentId);
      
      // If email exists for a different student_id, reject
      if (!emailStudentIds.includes(currentStudentId)) {
        console.log(`❌ Email ${email} already exists for different student_id(s): ${emailStudentIds.join(', ')}`);
        return res.status(400).json({ 
          success: false, 
          error: 'This email is already registered to another account. Please use a different email address.' 
        });
      }
      
      // Email exists for the same student_id (multiple year records) - this is okay
      console.log(`✅ Email ${email} exists for same student_id ${studentId} - allowed (multiple year records)`);
    }

    // Verify the code
    const storedCode = verificationCodes.get(studentId);
    if (!storedCode) {
      return res.status(400).json({ success: false, error: 'Verification code not found. Please request a new code.' });
    }

    if (Date.now() > storedCode.expiresAt) {
      verificationCodes.delete(studentId);
      return res.status(400).json({ success: false, error: 'Verification code has expired. Please request a new code.' });
    }

    if (storedCode.code !== verificationCode) {
      return res.status(400).json({ success: false, error: 'Invalid verification code' });
    }

    if (storedCode.email !== email) {
      return res.status(400).json({ success: false, error: 'Email does not match the one used for verification' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ success: false, error: 'Passwords do not match' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password and email in database (update all records for this student_id)
    // First, check what the actual password column name is
    try {
      const [columns] = await pool.execute('DESCRIBE students');
      console.log('📋 All columns in students table:', columns.map((c) => c.Field).join(', '));
      
      // Find password column (check common variations and case-insensitive)
      const passwordColumn = columns.find((col) => {
        if (!col.Field) return false;
        const fieldName = col.Field.toLowerCase();
        return fieldName === 'password' || 
               fieldName === 'pass' || 
               fieldName === 'user_password' || 
               fieldName === 'pwd' ||
               fieldName.includes('password');
      });
      
      if (!passwordColumn) {
        console.error('❌ Password column not found in students table');
        console.log('📋 Available columns:', columns.map((c) => c.Field).join(', '));
        return res.status(500).json({ 
          success: false, 
          error: 'Database configuration error: Password column not found. Please check your database schema.' 
        });
      }
      
      const passwordColumnName = passwordColumn.Field;
      console.log(`✅ Found password column: "${passwordColumnName}"`);
      
      // First, check how many records will be updated
      const [recordsToUpdate] = await pool.execute(
        'SELECT COUNT(*) as count FROM students WHERE student_id = ?',
        [studentId]
      );
      const recordCount = recordsToUpdate[0]?.count || 0;
      console.log(`📊 Found ${recordCount} record(s) with student_id: ${studentId}`);
      
      // Use backticks to handle reserved words or special characters
      // This UPDATE will update ALL records with the same student_id
      const [updateResult] = await pool.execute(
        `UPDATE students SET \`${passwordColumnName}\` = ?, email = ? WHERE student_id = ?`,
        [hashedPassword, email, studentId]
      );
      
      const affectedRows = updateResult.affectedRows || 0;
      console.log(`✅ Successfully updated ${affectedRows} record(s) with password and email for student_id: ${studentId}`);
      
      if (affectedRows !== recordCount) {
        console.warn(`⚠️ Warning: Expected to update ${recordCount} records but only ${affectedRows} were updated`);
      }
    } catch (updateError) {
      console.error('❌ Error updating password:', updateError);
      console.error('Error code:', updateError.code);
      console.error('Error message:', updateError.message);
      return res.status(500).json({ 
        success: false, 
        error: 'Failed to update password: ' + updateError.message 
      });
    }

    // Remove used verification code
    verificationCodes.delete(studentId);

    // Generate JWT token
    const [allStudentRecords] = await pool.execute(
      'SELECT * FROM students WHERE student_id = ? ORDER BY year DESC',
      [studentId]
    );

    if (allStudentRecords.length === 0) {
      return res.status(404).json({ success: false, error: 'Student not found' });
    }

    const firstRecord = allStudentRecords[0];
    const availableYears = [...new Set(allStudentRecords.map(s => s.year))];
    
    const token = jwt.sign(
      { studentId: firstRecord.student_id, id: firstRecord.id },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log(`✅ Password and email set successfully for student: ${studentId}`);

    res.json({
      success: true,
      token,
      student: {
        id: firstRecord.id,
        studentId: firstRecord.student_id,
        firstName: firstRecord.first_name,
        lastName: firstRecord.last_name,
        middleInitial: firstRecord.middle_initial,
        email: firstRecord.email,
        gradeLevel: firstRecord.grade_level,
        lrn: firstRecord.lrn,
        guardianName: firstRecord.guardian,
        phoneNumber: firstRecord.phone_number,
        profilePhoto: firstRecord.image,
        year: firstRecord.year,
        semester: firstRecord.semester,
        availableYears: availableYears,
      }
    });
  } catch (error) {
    console.error('Set password error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Get payments/statement of account
app.get('/api/payments', authenticateToken, async (req, res) => {
  try {
    const studentId = req.studentId;
    const year = req.query.year; // Get year from query parameter

    console.log(`📊 Fetching payments for student: ${studentId}, year: ${year || 'all'}`);

    // Get student info for fees - filter by year if provided
    let students;
    try {
      if (year) {
        [students] = await pool.execute(
          'SELECT * FROM students WHERE student_id = ? AND year = ?',
          [studentId, year]
        );
      } else {
        // If no year specified, get the most recent year
        // Try to get from year table first, then match with students
        const [recentYear] = await pool.execute(
          'SELECT year_name FROM year ORDER BY year_id DESC LIMIT 1'
        );
        
        if (recentYear.length > 0) {
          const defaultYear = recentYear[0].year_name;
          [students] = await pool.execute(
            'SELECT * FROM students WHERE student_id = ? AND year = ? LIMIT 1',
            [studentId, defaultYear]
          );
        } else {
          // Fallback: get first available student record
          [students] = await pool.execute(
            'SELECT * FROM students WHERE student_id = ? LIMIT 1',
            [studentId]
          );
        }
      }
    } catch (studentError) {
      console.error('❌ Error fetching student for payments:', studentError);
      return res.status(500).json({ error: 'Error fetching student data: ' + studentError.message });
    }

    if (students.length === 0) {
      return res.status(404).json({ error: 'Student not found for the specified year' });
    }

    const student = students[0];
    const selectedYear = student.year;

    // Get payment history for this year
    let payments = [];
    try {
      [payments] = await pool.execute(
        'SELECT * FROM payment_history WHERE student_id = ? AND p_year = ? ORDER BY p_date DESC, p_time DESC',
        [studentId, selectedYear]
      );
      payments = payments || [];
    } catch (paymentError) {
      console.error('❌ Error fetching payment history:', paymentError);
      payments = [];
    }

    // Calculate totals using current balance columns (remaining balance)
    const registration = parseFloat(student.registration || 0);
    const tuition = parseFloat(student.tuition || 0);
    const misc = parseFloat(student.misc || 0);
    const book = parseFloat(student.book || 0);
    const otherFee = parseFloat(student.other_fee || 0);
    
    // Current remaining balance (sum of all current balance columns)
    const balance = registration + tuition + misc + book + otherFee;

    // Get fixed academic year fees (for display purposes)
    const yearlyRegistration = parseFloat(student.yearly_registration || 0);
    const yearlyTuition = parseFloat(student.yearly_tuition || 0);
    const yearlyMisc = parseFloat(student.yearly_misc || 0);
    const yearlyBook = parseFloat(student.yearly_book || 0);
    const yearlyOtherFee = parseFloat(student.yearly_other_fee || 0);
    
    const totalRequired = yearlyRegistration + yearlyTuition + yearlyMisc + yearlyBook + yearlyOtherFee;
    const totalPaid = totalRequired - balance;

    // Format required fees with current remaining balance
    const requiredFees = [];
    if (yearlyRegistration > 0) {
      requiredFees.push({ 
        description: 'Registration Fee', 
        amount: registration, // Current remaining balance
        totalAmount: yearlyRegistration, // Original fee
        dueDate: `${selectedYear}-12-31` 
      });
    }
    if (yearlyTuition > 0) {
      requiredFees.push({ 
        description: 'Tuition Fee', 
        amount: tuition, 
        totalAmount: yearlyTuition,
        dueDate: `${selectedYear}-12-31` 
      });
    }
    if (yearlyMisc > 0) {
      requiredFees.push({ 
        description: 'Miscellaneous Fee', 
        amount: misc, 
        totalAmount: yearlyMisc,
        dueDate: `${selectedYear}-12-31` 
      });
    }
    if (yearlyBook > 0) {
      requiredFees.push({ 
        description: 'Book Fee', 
        amount: book, 
        totalAmount: yearlyBook,
        dueDate: `${selectedYear}-12-31` 
      });
    }
    if (yearlyOtherFee > 0) {
      requiredFees.push({ 
        description: 'Other Fee', 
        amount: otherFee, 
        totalAmount: yearlyOtherFee,
        dueDate: `${selectedYear}-12-31` 
      });
    }

    // Format payment history with breakdown by collection type
    const history = payments.map(p => {
      const paymentDate = p.p_date instanceof Date 
        ? p.p_date.toISOString().split('T')[0]
        : new Date(p.p_date).toISOString().split('T')[0];
      
      // Parse collection amounts
      const registration = parseFloat(p.p_registration || 0);
      const tuition = parseFloat(p.p_tuition || 0);
      const misc = parseFloat(p.p_misc || 0);
      const book = parseFloat(p.p_book || 0);
      const others = parseFloat(p.p_others || 0);
      
      // Build breakdown object (only include non-zero values)
      const breakdown = {};
      if (registration > 0) breakdown.registration = registration;
      if (tuition > 0) breakdown.tuition = tuition;
      if (misc > 0) breakdown.misc = misc;
      if (book > 0) breakdown.book = book;
      if (others > 0) breakdown.others = others;
      
      // Format time if it exists (handle both Date objects and strings)
      let time = null;
      if (p.p_time) {
        if (p.p_time instanceof Date) {
          // Format to 12-hour format with AM/PM
          const hours = p.p_time.getHours();
          const minutes = p.p_time.getMinutes();
          const ampm = hours >= 12 ? 'PM' : 'AM';
          const displayHours = hours % 12 || 12;
          time = `${String(displayHours).padStart(2, '0')}:${String(minutes).padStart(2, '0')} ${ampm}`;
        } else if (typeof p.p_time === 'string') {
          // If it's already a string, use it as is (preserves existing format like "05:54 PM")
          time = p.p_time;
        }
      }
      
      const paymentObj = {
        date: paymentDate,
        description: `Payment - ${p.p_semester || ''} ${p.p_year || ''}`,
        amount: parseFloat(p.p_total || 0),
        orNumber: p.or_no,
        breakdown: Object.keys(breakdown).length > 0 ? breakdown : undefined,
      };
      
      // Only include time if it exists
      if (time) {
        paymentObj.time = time;
      }
      
      return paymentObj;
    });

    res.json({
      balance,
      balanceBreakdown: {
        registration: registration,
        tuition: tuition,
        misc: misc,
        book: book,
        other_fee: otherFee,
      },
      totalRequired,
      totalPaid,
      requiredFees,
      history,
      year: selectedYear,
    });
  } catch (error) {
    console.error('❌ Payments error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

// Get attendance records
app.get('/api/attendance', authenticateToken, async (req, res) => {
  try {
    const studentId = req.studentId;
    const year = req.query.year; // Get year from query parameter

    console.log(`📊 Fetching attendance for student: ${studentId}, year: ${year || 'all'}`);

    // Get student info - filter by year if provided
    let students;
    if (year) {
      [students] = await pool.execute(
        'SELECT * FROM students WHERE student_id = ? AND year = ?',
        [studentId, year]
      );
    } else {
      // If no year specified, get the most recent year
      [students] = await pool.execute(
        'SELECT * FROM students WHERE student_id = ? ORDER BY year DESC LIMIT 1',
        [studentId]
      );
    }

    // If no student found for the year, return empty data instead of error
    if (students.length === 0) {
      return res.json({
        attendance: {},
        summary: { present: 0, absent: 0, excused: 0, timeInOnly: 0, timeOutOnly: 0, holiday: 0 },
        holidays: {},
        excuses: {},
      });
    }

    // Parse year to get start and end years (e.g., "2024-2025" -> 2024 and 2025)
    let yearStart = null;
    let yearEnd = null;
    if (year) {
      const yearParts = year.split('-');
      if (yearParts.length === 2) {
        yearStart = parseInt(yearParts[0]);
        yearEnd = parseInt(yearParts[1]);
      }
    }

    // Get school span to determine starting date for absence counting
    // Use id = 1 (as specified by user)
    let startingOfClasses = null;
    try {
      const [schoolSpan] = await pool.execute(
        'SELECT starting_of_classes FROM school_span WHERE id = 1'
      );
      
      if (schoolSpan.length > 0 && schoolSpan[0].starting_of_classes) {
        startingOfClasses = schoolSpan[0].starting_of_classes instanceof Date
          ? schoolSpan[0].starting_of_classes
          : new Date(schoolSpan[0].starting_of_classes);
      }
    } catch (schoolSpanError) {
      console.log('⚠️  School span table query error (may not exist):', schoolSpanError.message);
    }

    // Get holidays - handle case where table might not exist or have different structure
    let holidays = [];
    try {
      const [holidayResults] = await pool.execute(
        'SELECT * FROM holidays ORDER BY holiday_date DESC'
      );
      holidays = holidayResults || [];
    } catch (holidayError) {
      console.log('⚠️  Holidays table query error (may not exist):', holidayError.message);
      holidays = [];
    }

    // Get excuses for this student_id
    let excuses = [];
    try {
      const [excuseResults] = await pool.execute(
        'SELECT * FROM excuses WHERE student_id = ?',
        [studentId]
      );
      excuses = excuseResults || [];
    } catch (excuseError) {
      console.log('⚠️  Excuses table query error (may not exist):', excuseError.message);
      excuses = [];
    }

    // Get attendance records for this student_id and year
    let attendanceRecords = [];
    try {
      if (year) {
        // Filter by year column in attendance table
        [attendanceRecords] = await pool.execute(
          'SELECT * FROM attendance WHERE student_id = ? AND year = ? ORDER BY date ASC, time ASC',
          [studentId, year]
        );
      } else {
        // If no year specified, get the most recent year from year table and use it
        const [recentYear] = await pool.execute(
          'SELECT year_name FROM year ORDER BY year_id DESC LIMIT 1'
        );
        
        if (recentYear.length > 0) {
          const defaultYear = recentYear[0].year_name;
          [attendanceRecords] = await pool.execute(
            'SELECT * FROM attendance WHERE student_id = ? AND year = ? ORDER BY date ASC, time ASC',
            [studentId, defaultYear]
          );
        } else {
          // If no year in year table, get all records
          [attendanceRecords] = await pool.execute(
            'SELECT * FROM attendance WHERE student_id = ? ORDER BY date ASC, time ASC',
            [studentId]
          );
        }
      }
      attendanceRecords = attendanceRecords || [];
    } catch (attendanceError) {
      console.error('❌ Attendance table query error:', attendanceError);
      return res.status(500).json({ error: 'Error fetching attendance records: ' + attendanceError.message });
    }

    // Create a map of holidays
    const holidayMap = {};
    holidays.forEach(h => {
      try {
        let date;
        if (h.holiday_date) {
          if (h.holiday_date instanceof Date) {
            date = h.holiday_date.toISOString().split('T')[0];
          } else {
            date = new Date(h.holiday_date).toISOString().split('T')[0];
          }
        } else {
          return; // Skip if no holiday_date
        }
        
        holidayMap[date] = { 
          type: 'holiday', 
          description: (h.description !== undefined && h.description !== null) ? h.description : 'Holiday' // Use 'Holiday' as default if description doesn't exist
        };
      } catch (dateError) {
        console.log('⚠️  Error processing holiday date:', dateError.message);
      }
    });

    // Process attendance records by date
    const attendanceMap = {};
    const summary = { present: 0, absent: 0, excused: 0, timeInOnly: 0, timeOutOnly: 0, holiday: 0 };

    // Group attendance records by date
    attendanceRecords.forEach(record => {
      try {
        let date;
        if (record.date) {
          if (record.date instanceof Date) {
            date = record.date.toISOString().split('T')[0];
          } else {
            date = new Date(record.date).toISOString().split('T')[0];
          }
        } else {
          return; // Skip if no date
        }
        
        if (!attendanceMap[date]) {
          attendanceMap[date] = {
            date,
            timeIn: null,
            timeOut: null,
            timeInRecord: null,
            timeOutRecord: null,
          };
        }

        // Store time-in and time-out records
        if (record.status === 'TIME-IN' || record.status === 'TIME IN') {
          if (record.time) {
            attendanceMap[date].timeIn = record.time instanceof Date 
              ? record.time.toTimeString().slice(0, 5)
              : typeof record.time === 'string' 
                ? record.time.slice(0, 5)
                : String(record.time).slice(0, 5);
            attendanceMap[date].timeInRecord = record;
          }
        } else if (record.status === 'TIME-OUT' || record.status === 'TIME OUT') {
          if (record.time) {
            attendanceMap[date].timeOut = record.time instanceof Date 
              ? record.time.toTimeString().slice(0, 5)
              : typeof record.time === 'string' 
                ? record.time.slice(0, 5)
                : String(record.time).slice(0, 5);
            attendanceMap[date].timeOutRecord = record;
          }
        }
      } catch (recordError) {
        console.log('⚠️  Error processing attendance record:', recordError.message);
      }
    });

    // Determine status for each date
    const attendanceData = {};
    const allDates = new Set();
    
    // Add all dates from attendance records
    Object.keys(attendanceMap).forEach(date => allDates.add(date));
    
    // Add all holiday dates (even if no attendance records)
    Object.keys(holidayMap).forEach(date => allDates.add(date));
    
    // Add all excuse dates (even if no attendance records)
    excuses.forEach(e => {
      try {
        if (e.excuse_date) {
          const excuseDate = e.excuse_date instanceof Date 
            ? e.excuse_date.toISOString().split('T')[0]
            : new Date(e.excuse_date).toISOString().split('T')[0];
          allDates.add(excuseDate);
        }
      } catch (excuseError) {
        console.log('⚠️  Error processing excuse date:', excuseError.message);
      }
    });

    // Get current date in UTC+8 (Philippines timezone)
    const now = new Date();
    const philippinesTime = new Date(now.toLocaleString("en-US", {timeZone: "Asia/Manila"}));
    const todayStr = philippinesTime.toISOString().split('T')[0];

    // Process each date - priority: Holiday > Excused > Attendance
    allDates.forEach(dateStr => {
      const record = attendanceMap[dateStr];
      
      // Check if holiday FIRST (holidays take priority)
      if (holidayMap[dateStr]) {
        attendanceData[dateStr] = {
          type: 'holiday',
          description: holidayMap[dateStr].description || 'Holiday', // Default description if column doesn't exist
        };
        summary.holiday++;
        return;
      }

      // Check if excused (check if excuse_date matches this date)
      let isExcused = false;
      let excuse = null;
      try {
        isExcused = excuses.some(e => {
          if (!e.excuse_date) return false;
          const excuseDate = e.excuse_date instanceof Date 
            ? e.excuse_date.toISOString().split('T')[0]
            : new Date(e.excuse_date).toISOString().split('T')[0];
          return excuseDate === dateStr;
        });

        if (isExcused) {
          excuse = excuses.find(e => {
            if (!e.excuse_date) return false;
            const excuseDate = e.excuse_date instanceof Date 
              ? e.excuse_date.toISOString().split('T')[0]
              : new Date(e.excuse_date).toISOString().split('T')[0];
            return excuseDate === dateStr;
          });
        }
      } catch (excuseCheckError) {
        console.log('⚠️  Error checking excuse:', excuseCheckError.message);
      }

      // Check if excused
      if (isExcused && excuse) {
        attendanceData[dateStr] = {
          type: 'excused',
          remarks: (excuse.remarks !== undefined && excuse.remarks !== null) ? excuse.remarks : '',
        };
        summary.excused++;
        return;
      }

      // Determine status based on TIME-IN and TIME-OUT (only if we have attendance records)
      if (record) {
        if (record.timeIn && record.timeOut) {
          // Both TIME-IN and TIME-OUT present
          attendanceData[dateStr] = {
            type: 'present',
            timeIn: record.timeIn,
            timeOut: record.timeOut,
          };
          summary.present++;
        } else if (record.timeIn && !record.timeOut) {
          // Only TIME-IN
          attendanceData[dateStr] = {
            type: 'timeInOnly',
            timeIn: record.timeIn,
          };
          summary.timeInOnly++;
        } else if (!record.timeIn && record.timeOut) {
          // Only TIME-OUT
          attendanceData[dateStr] = {
            type: 'timeOutOnly',
            timeOut: record.timeOut,
          };
          summary.timeOutOnly++;
        } else {
          // Has attendance record but no TIME-IN or TIME-OUT - mark as absent
          attendanceData[dateStr] = {
            type: 'absent',
          };
          summary.absent++;
        }
      }
      // Note: We don't mark dates without attendance records as absent here
      // because we only process dates that have records, holidays, or excuses
      // Absent dates should be determined on the frontend for the visible calendar month
    });

    // Also include excuses in the response for frontend to use
    const excuseMap = {};
    excuses.forEach(e => {
      try {
        if (e.excuse_date) {
          const date = e.excuse_date instanceof Date 
            ? e.excuse_date.toISOString().split('T')[0]
            : new Date(e.excuse_date).toISOString().split('T')[0];
          excuseMap[date] = { 
            type: 'excused', 
            remarks: (e.remarks !== undefined && e.remarks !== null) ? e.remarks : '' 
          };
        }
      } catch (excuseMapError) {
        console.log('⚠️  Error mapping excuse:', excuseMapError.message);
      }
    });

    // Calculate absent count from starting_of_classes to today, but only for dates within the selected year
    // Use UTC+8 timezone (Philippines) for all date calculations
    if (startingOfClasses) {
      // Get current date in UTC+8 (Philippines timezone)
      // Convert UTC time to UTC+8 by adding 8 hours
      const now = new Date();
      const utcTime = now.getTime() + (now.getTimezoneOffset() * 60000);
      const philippinesTime = new Date(utcTime + (8 * 3600000)); // UTC+8 = 8 hours in milliseconds
      const today = new Date(philippinesTime.getFullYear(), philippinesTime.getMonth(), philippinesTime.getDate());
      today.setHours(0, 0, 0, 0);
      
      // Convert starting_of_classes to UTC+8 timezone
      // Handle startingOfClasses as either Date object or string
      let startDate;
      if (startingOfClasses instanceof Date) {
        // If it's already a Date object, use it directly
        startDate = new Date(startingOfClasses);
      } else if (typeof startingOfClasses === 'string') {
        // If it's a string, parse it
        const startDateParts = startingOfClasses.split('-');
        startDate = new Date(
          parseInt(startDateParts[0]), // year
          parseInt(startDateParts[1]) - 1, // month (0-indexed)
          parseInt(startDateParts[2]) // day
        );
      } else {
        // Fallback: try to create Date from the value
        startDate = new Date(startingOfClasses);
      }
      startDate.setHours(0, 0, 0, 0);
      
      // If year is specified, limit the date range to that year
      let endDate = today;
      if (yearStart && yearEnd) {
        // Set end date to the end of the school year (e.g., 2025-12-31 for 2024-2025)
        // Create date in UTC+8 timezone (treat as local date)
        endDate = new Date(parseInt(yearEnd), 11, 31); // December 31 of end year
        endDate.setHours(23, 59, 59, 999);
        
        // Also limit start date to beginning of school year if starting_of_classes is before it
        const yearStartDate = new Date(parseInt(yearStart), 0, 1); // January 1 of start year
        yearStartDate.setHours(0, 0, 0, 0);
        
        if (startDate < yearStartDate) {
          startDate.setTime(yearStartDate.getTime());
        }
      }
      
      // Don't count dates beyond today (in UTC+8)
      if (endDate > today) {
        endDate = today;
      }
      
      // Reset absent count to recalculate
      summary.absent = 0;
      
      // Iterate through all dates from starting_of_classes to endDate (or today, whichever is earlier)
      // All date operations use UTC+8 timezone (dates are treated as local dates in UTC+8)
      const currentDate = new Date(startDate);
      while (currentDate <= endDate) {
        // Format date string (dates are already in UTC+8 context)
        const year = currentDate.getFullYear();
        const month = String(currentDate.getMonth() + 1).padStart(2, '0');
        const day = String(currentDate.getDate()).padStart(2, '0');
        const dateStr = `${year}-${month}-${day}`;
        
        const currentYear = currentDate.getFullYear();
        const dayOfWeek = currentDate.getDay();
        
        // Only process dates within the selected school year range
        let isWithinYearRange = true;
        if (yearStart && yearEnd) {
          isWithinYearRange = (currentYear === yearStart || currentYear === yearEnd);
        }
        
        // Only count weekdays (Monday-Friday, where 0=Sunday, 6=Saturday) within year range
        // Exclude weekends (Saturday and Sunday) from absence counting
        if (isWithinYearRange) {
          // Skip weekends completely - don't process them at all
          if (dayOfWeek === 0 || dayOfWeek === 6) {
            // It's a weekend (Saturday or Sunday), skip to next day
            currentDate.setDate(currentDate.getDate() + 1);
            continue;
          }
          
          // Only process weekdays (Monday-Friday)
          // Check if date is a holiday by checking holidayMap (from holidays table)
          const isHoliday = holidayMap[dateStr];
          
          // If it's a holiday, don't count as absent - skip this date
          if (isHoliday) {
            // Date is a holiday, skip absence counting
            currentDate.setDate(currentDate.getDate() + 1);
            continue;
          }
          
          // Check if date is not excused
          const isExcused = excuseMap[dateStr];
          
          // Check if date has attendance record
          const hasAttendance = attendanceData[dateStr];
          
          // If not excused and no attendance record (or incomplete attendance), count as absent
          if (!isExcused) {
            if (!hasAttendance) {
              // No attendance record at all - mark as absent
              attendanceData[dateStr] = {
                type: 'absent',
              };
              summary.absent++;
            } else if (hasAttendance.type === 'timeInOnly' || hasAttendance.type === 'timeOutOnly') {
              // Incomplete attendance (only TIME-IN or only TIME-OUT) - count as absent
              summary.absent++;
            }
            // If hasAttendance.type === 'present', don't count as absent
          }
        }
        
        // Move to next day
        currentDate.setDate(currentDate.getDate() + 1);
      }
    }

    // Get raw attendance records from attendance table for the list (date, time, status)
    let rawRecords = [];
    try {
      if (year) {
        [rawRecords] = await pool.execute(
          'SELECT id, date, time, status FROM attendance WHERE student_id = ? AND year = ? ORDER BY id DESC',
          [studentId, year]
        );
      } else {
        // If no year specified, get the most recent year from year table and use it
        const [recentYear] = await pool.execute(
          'SELECT year_name FROM year ORDER BY year_id DESC LIMIT 1'
        );
        
        if (recentYear.length > 0) {
          const defaultYear = recentYear[0].year_name;
          [rawRecords] = await pool.execute(
            'SELECT id, date, time, status FROM attendance WHERE student_id = ? AND year = ? ORDER BY id DESC',
            [studentId, defaultYear]
          );
        } else {
          [rawRecords] = await pool.execute(
            'SELECT id, date, time, status FROM attendance WHERE student_id = ? ORDER BY id DESC',
            [studentId]
          );
        }
      }
      rawRecords = rawRecords || [];
    } catch (rawRecordsError) {
      console.error('❌ Error fetching raw attendance records:', rawRecordsError);
      rawRecords = [];
    }

    // Format raw records for response - preserve time format as stored in database
    const formattedRecords = rawRecords.map(record => {
      const date = record.date instanceof Date 
        ? record.date.toISOString().split('T')[0]
        : new Date(record.date).toISOString().split('T')[0];
      
      // Preserve the time format as stored in database (e.g., "05:54 PM")
      let time = '';
      if (record.time) {
        if (typeof record.time === 'string') {
          // If it's already a string, use it as is (preserves "05:54 PM" format)
          time = record.time;
        } else if (record.time instanceof Date) {
          // If it's a Date object, format it to 12-hour format with AM/PM
          const hours = record.time.getHours();
          const minutes = record.time.getMinutes();
          const ampm = hours >= 12 ? 'PM' : 'AM';
          const displayHours = hours % 12 || 12;
          time = `${String(displayHours).padStart(2, '0')}:${String(minutes).padStart(2, '0')} ${ampm}`;
        } else {
          // Fallback: convert to string
          time = String(record.time);
        }
      }
      
      return {
        date,
        time,
        status: record.status || '',
      };
    });

    console.log(`✅ Attendance data fetched: ${Object.keys(attendanceData).length} dates, ${summary.present} present, ${summary.absent} absent, ${formattedRecords.length} raw records`);

    res.json({
      attendance: attendanceData,
      records: formattedRecords, // Raw records from attendance table (date, time, status)
      summary,
      holidays: holidayMap,
      excuses: excuseMap,
    });
  } catch (error) {
    console.error('❌ Attendance error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

// Get years for filter - get all years from year table
app.get('/api/years', authenticateToken, async (req, res) => {
  try {
    // Get all years from year table in descending order by year_id
    const [years] = await pool.execute(
      'SELECT * FROM year ORDER BY year_id DESC'
    );

    res.json({
      success: true,
      years: years.map(y => ({
        id: y.year_id,
        yearName: y.year_name,
        year: y.year_name, // Use year_name as the year value for filtering
      })),
    });
  } catch (error) {
    console.error('Years error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

// Register push token endpoint
// Push tokens are stored in a separate table: student_push_tokens
// Table structure: id, student_id, push_token, device_info, created_at, updated_at
app.post('/api/push-token', authenticateToken, async (req, res) => {
  try {
    const studentId = req.studentId;
    const { pushToken, deviceInfo } = req.body;

    if (!pushToken) {
      return res.status(400).json({ success: false, error: 'Push token is required' });
    }

    // Check if student_push_tokens table exists, if not create it
    try {
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS student_push_tokens (
          id INT AUTO_INCREMENT PRIMARY KEY,
          student_id VARCHAR(50) NOT NULL,
          push_token TEXT NOT NULL,
          device_info VARCHAR(255),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          UNIQUE KEY unique_student_token (student_id, push_token(255)),
          INDEX idx_student_id (student_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
      `);
    } catch (tableError) {
      console.log('📋 student_push_tokens table check:', tableError.message);
    }

    // Update or insert push token in student_push_tokens table
    // Use INSERT ... ON DUPLICATE KEY UPDATE or REPLACE
    try {
      await pool.execute(
        'INSERT INTO student_push_tokens (student_id, push_token, device_info, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE push_token = ?, device_info = ?, updated_at = NOW()',
        [studentId, pushToken, deviceInfo || null, pushToken, deviceInfo || null]
      );
    } catch (insertError) {
      // If ON DUPLICATE KEY doesn't work, try UPDATE first then INSERT
      const [existing] = await pool.execute(
        'SELECT id FROM student_push_tokens WHERE student_id = ? AND push_token = ?',
        [studentId, pushToken]
      );

      if (existing.length > 0) {
        await pool.execute(
          'UPDATE student_push_tokens SET device_info = ?, updated_at = NOW() WHERE student_id = ? AND push_token = ?',
          [deviceInfo || null, studentId, pushToken]
        );
      } else {
        // Remove old token for this student and insert new one (one token per student)
        await pool.execute(
          'DELETE FROM student_push_tokens WHERE student_id = ?',
          [studentId]
        );
        await pool.execute(
          'INSERT INTO student_push_tokens (student_id, push_token, device_info, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())',
          [studentId, pushToken, deviceInfo || null]
        );
      }
    }

    console.log(`✅ Push token registered for student: ${studentId}`);
    res.json({ success: true, message: 'Push token registered successfully' });
  } catch (error) {
    console.error('❌ Error registering push token:', error);
    res.status(500).json({ success: false, error: 'Internal server error: ' + error.message });
  }
});

// Get notifications from notifications table
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const studentId = req.studentId;
    const year = req.query.year; // Get year from query parameter (optional)

    console.log(`📊 Fetching notifications for student: ${studentId}, year: ${year || 'all'}`);

    // Query notifications table - using correct column names from Railway
    // Note: 'read' is a reserved keyword in MySQL, so we need to escape it with backticks
    let query = 'SELECT id, student_id, type, title, message, date, year, time, `read` FROM notifications WHERE student_id = ?';
    let params = [studentId];

    if (year) {
      // Filter by year column if provided
      query += ' AND year = ?';
      params.push(year);
    }

    query += ' ORDER BY date DESC, time DESC LIMIT 50';

    const [notifications] = await pool.execute(query, params);

    // Convert database format to API format
    const formattedNotifications = notifications.map((notif) => ({
      id: notif.id,
      type: notif.type || 'announcement',
      title: notif.title || getNotificationTitle(notif.type),
      message: notif.message || '',
      date: notif.date instanceof Date 
        ? notif.date.toISOString().split('T')[0]
        : (notif.date || new Date().toISOString().split('T')[0]),
      read: notif.read === 1 || notif.read === true || notif.read === '1',
    }));

    const unreadCount = formattedNotifications.filter(n => !n.read).length;

    res.json({
      success: true,
      unreadCount,
      notifications: formattedNotifications,
    });
  } catch (error) {
    console.error('❌ Notifications error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ success: false, error: 'Internal server error: ' + error.message });
  }
});

// Mark a single notification as read
app.post('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const studentId = req.studentId;
    const notificationId = parseInt(req.params.id);

    if (isNaN(notificationId)) {
      return res.status(400).json({ success: false, error: 'Invalid notification ID' });
    }

    console.log(`📝 Marking notification ${notificationId} as read for student: ${studentId}`);

    // Update the read status to 1 (true) for this notification
    // Only allow updating notifications that belong to this student
    // Note: 'read' is a reserved keyword in MySQL, so we need to escape it with backticks
    const [result] = await pool.execute(
      'UPDATE notifications SET `read` = 1 WHERE id = ? AND student_id = ?',
      [notificationId, studentId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Notification not found or does not belong to this student' 
      });
    }

    console.log(`✅ Notification ${notificationId} marked as read`);

    res.json({
      success: true,
      message: 'Notification marked as read',
    });
  } catch (error) {
    console.error('❌ Error marking notification as read:', error);
    res.status(500).json({ success: false, error: 'Internal server error: ' + error.message });
  }
});

// Mark all notifications as read for a student
app.post('/api/notifications/mark-all-read', authenticateToken, async (req, res) => {
  try {
    const studentId = req.studentId;
    const year = req.query.year; // Optional year filter

    console.log(`📝 Marking all notifications as read for student: ${studentId}, year: ${year || 'all'}`);

    // Note: 'read' is a reserved keyword in MySQL, so we need to escape it with backticks
    let query = 'UPDATE notifications SET `read` = 1 WHERE student_id = ? AND `read` = 0';
    let params = [studentId];

    if (year) {
      query += ' AND year = ?';
      params.push(year);
    }

    const [result] = await pool.execute(query, params);

    console.log(`✅ ${result.affectedRows} notification(s) marked as read`);

    res.json({
      success: true,
      message: `${result.affectedRows} notification(s) marked as read`,
      affectedRows: result.affectedRows,
    });
  } catch (error) {
    console.error('❌ Error marking all notifications as read:', error);
    res.status(500).json({ success: false, error: 'Internal server error: ' + error.message });
  }
});

// Helper function to get notification title based on type
function getNotificationTitle(type) {
  switch (type) {
    case 'payment':
      return 'Payment Received';
    case 'attendance':
      return 'Attendance Recorded';
    case 'announcement':
      return 'Announcement';
    default:
      return 'Notification';
  }
}

// Get grade levels for a student
app.get('/api/grade-levels', authenticateToken, async (req, res) => {
  try {
    const studentId = req.user.studentId;
    
    // Get all unique grade levels for this student
    const [gradeLevels] = await pool.execute(
      'SELECT DISTINCT grade_level FROM students WHERE student_id = ? AND grade_level IS NOT NULL AND grade_level != "" ORDER BY grade_level ASC',
      [studentId]
    );
    
    const gradeLevelList = gradeLevels.map((row) => row.grade_level);
    
    res.json({
      success: true,
      gradeLevels: gradeLevelList,
    });
  } catch (error) {
    console.error('❌ Error fetching grade levels:', error);
    res.status(500).json({ success: false, error: 'Error fetching grade levels: ' + error.message });
  }
});

// Get signatories - get School Cashier
app.get('/api/signatories', authenticateToken, async (req, res) => {
  try {
    const designation = req.query.designation || 'School Cashier';
    
    // Get signatory with the specified designation
    const [signatories] = await pool.execute(
      'SELECT * FROM signatories WHERE Designation = ? LIMIT 1',
      [designation]
    );
    
    if (signatories.length === 0) {
      return res.json({
        success: true,
        name: null,
        designation: designation,
      });
    }
    
    const signatory = signatories[0];
    // Find the name column (could be 'name', 'Name', 'full_name', etc.)
    const nameColumn = Object.keys(signatory).find(key => 
      key.toLowerCase().includes('name') && 
      signatory[key] !== null && 
      signatory[key] !== undefined
    );
    
    res.json({
      success: true,
      name: nameColumn ? signatory[nameColumn] : null,
      designation: designation,
    });
  } catch (error) {
    console.error('❌ Error fetching signatories:', error);
    res.status(500).json({ success: false, error: 'Error fetching signatories: ' + error.message });
  }
});

// Get student data by year
app.get('/api/student', authenticateToken, async (req, res) => {
  try {
    const studentId = req.studentId;
    const year = req.query.year; // Get year from query parameter
    
    console.log(`📊 Fetching student data for: ${studentId}, year: ${year || 'all'}`);
    
    let students;
    if (year) {
      [students] = await pool.execute(
        'SELECT * FROM students WHERE student_id = ? AND year = ? LIMIT 1',
        [studentId, year]
      );
    } else {
      // If no year specified, get the most recent year
      [students] = await pool.execute(
        'SELECT * FROM students WHERE student_id = ? ORDER BY year DESC LIMIT 1',
        [studentId]
      );
    }
    
    if (students.length === 0) {
      return res.status(404).json({ error: 'Student not found for the specified year' });
    }
    
    const student = students[0];
    
    res.json({
      success: true,
      student: {
        id: student.id,
        studentId: student.student_id,
        firstName: student.first_name,
        lastName: student.last_name,
        middleInitial: student.middle_initial,
        email: student.email,
        gradeLevel: student.grade_level,
        lrn: student.lrn,
        phoneNumber: student.phone_number,
        profilePhoto: student.image,
        year: student.year,
        semester: student.semester,
      }
    });
  } catch (error) {
    console.error('❌ Error fetching student data:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'KWAI Portal API is running' });
});

// Socket.IO connection handling
const connectedClients = new Map(); // studentId -> socketId

io.on('connection', (socket) => {
  console.log('🔌 Client connected:', socket.id);

  // Handle student authentication via socket
  socket.on('authenticate', async (data) => {
    try {
      const { token } = data;
      if (!token) {
        socket.emit('auth-error', { message: 'Token required' });
        return;
      }

      // Verify JWT token
      const decoded = jwt.verify(token, JWT_SECRET);
      const studentId = decoded.studentId || decoded.student_id;
      
      if (studentId) {
        connectedClients.set(studentId, socket.id);
        socket.studentId = studentId;
        socket.join(`student_${studentId}`);
        console.log(`✅ Socket authenticated for student: ${studentId}`);
        socket.emit('authenticated', { studentId });
      } else {
        socket.emit('auth-error', { message: 'Invalid token' });
      }
    } catch (error) {
      console.error('❌ Socket authentication error:', error);
      socket.emit('auth-error', { message: 'Authentication failed' });
    }
  });

  socket.on('disconnect', () => {
    if (socket.studentId) {
      connectedClients.delete(socket.studentId);
      console.log(`🔌 Client disconnected: ${socket.studentId}`);
    }
  });
});

// Database monitoring function - checks for new records
let lastPaymentCheck = {};
let lastAttendanceCheck = {};
let lastAttendanceId = 0; // Track the highest attendance ID we've seen

async function checkForNewRecords() {
  try {
    // Check payment_history for new records (using p_date and p_time)
    const [recentPayments] = await pool.execute(
      'SELECT p_id, student_id, p_total, or_no, p_date, p_time, p_year, p_semester, p_full_name FROM payment_history WHERE p_date >= DATE_SUB(NOW(), INTERVAL 5 MINUTE) ORDER BY p_date DESC, p_time DESC'
    );

    for (const payment of recentPayments) {
      const studentId = payment.student_id;
      const paymentKey = `${studentId}_${payment.p_id}`;

      if (!lastPaymentCheck[paymentKey]) {
        lastPaymentCheck[paymentKey] = true;

        // Format date and time for notification
        const paymentDate = payment.p_date instanceof Date 
          ? payment.p_date
          : new Date(payment.p_date);
        const dateStr = paymentDate.toISOString().split('T')[0];
        
        // Format time if available
        let timeStr = '';
        if (payment.p_time) {
          if (payment.p_time instanceof Date) {
            const hours = payment.p_time.getHours();
            const minutes = payment.p_time.getMinutes();
            const ampm = hours >= 12 ? 'PM' : 'AM';
            const displayHours = hours % 12 || 12;
            timeStr = `${String(displayHours).padStart(2, '0')}:${String(minutes).padStart(2, '0')} ${ampm}`;
          } else if (typeof payment.p_time === 'string') {
            // If it's already a string, try to parse it
            timeStr = payment.p_time;
          }
        }

        // Format date nicely (e.g., "Jan 12, 2026")
        const formattedDate = paymentDate.toLocaleDateString('en-PH', {
          year: 'numeric',
          month: 'short',
          day: 'numeric'
        });

        // Build notification message according to requirements:
        // "Payment Posted - Your new payment of ₱2,500 has been recorded on Jan 12, 2026 – 10:32 AM. Thank you for settling your school fees."
        const amount = parseFloat(payment.p_total || 0).toLocaleString('en-PH', { minimumFractionDigits: 2 });
        let message = `Your new payment of ₱${amount} has been recorded on ${formattedDate}`;
        if (timeStr) {
          message += ` – ${timeStr}`;
        }
        message += '. Thank you for settling your school fees.';

        const notificationTitle = 'Payment Posted';
        const fullMessage = message; // Store just the message, title is separate
        const year = payment.p_year || null; // Get year from payment record

        // Insert notification into notifications table
        // The table's id column doesn't have AUTO_INCREMENT, so we need to provide it manually
        try {
          // Get the maximum ID and increment it
          const [maxIdResult] = await pool.execute('SELECT MAX(id) as max_id FROM notifications');
          const nextId = (maxIdResult[0]?.max_id || 0) + 1;
          
          await pool.execute(
            'INSERT INTO notifications (id, student_id, type, title, message, date, year, time, `read`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [nextId, studentId, 'payment', notificationTitle, fullMessage, dateStr, year, payment.p_time || null, 0]
          );
        } catch (insertError) {
          // If duplicate key error, try with a higher ID
          if (insertError.code === 'ER_DUP_ENTRY') {
            const [maxIdResult] = await pool.execute('SELECT MAX(id) as max_id FROM notifications');
            const nextId = (maxIdResult[0]?.max_id || 0) + 10; // Add buffer to avoid conflicts
            await pool.execute(
              'INSERT INTO notifications (id, student_id, type, title, message, date, year, time, `read`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
              [nextId, studentId, 'payment', notificationTitle, fullMessage, dateStr, year, payment.p_time || null, 0]
            );
          } else {
            console.error('❌ Error inserting payment notification:', insertError);
            throw insertError;
          }
        }

        // Get push token from student_push_tokens table
        const [tokenRows] = await pool.execute(
          'SELECT push_token FROM student_push_tokens WHERE student_id = ? LIMIT 1',
          [studentId]
        );

        // Send push notification via Socket.IO (if client is connected)
        io.to(`student_${studentId}`).emit('notification', {
          type: 'payment',
          title: notificationTitle,
          message: message,
          date: dateStr,
        });

        if (tokenRows.length > 0) {
          console.log(`📤 Push notification sent to student ${studentId}: Payment received (via Socket.IO)`);
          // Here you could also send to external push notification service (FCM, etc.)
          // using tokenRows[0].push_token
        } else {
          console.log(`⚠️  No push token found for student ${studentId}, notification saved but not pushed`);
        }
      }
    }

    // Check attendance for new records
    // Note: attendance table columns: id, student_id, date, time, status, year
    // status is always either 'TIME-IN' or 'TIME-OUT'
    // Since there's no created_at column, we track by ID to detect new records
    const [recentAttendance] = await pool.execute(
      `SELECT a.id, a.student_id, a.date, a.time, a.status, a.year,
              s.first_name, s.last_name
       FROM attendance a
       INNER JOIN students s ON a.student_id = s.student_id
       WHERE a.id > ?
       AND a.date >= DATE_SUB(CURDATE(), INTERVAL 1 DAY)
       ORDER BY a.id DESC, a.date DESC, a.time DESC
       LIMIT 100`,
      [lastAttendanceId]
    );

    // Update the highest ID we've seen
    if (recentAttendance.length > 0) {
      lastAttendanceId = Math.max(lastAttendanceId, ...recentAttendance.map(r => r.id));
    }

    for (const record of recentAttendance) {
      const studentId = record.student_id;
      const attendanceKey = `${studentId}_${record.id}_${record.date}_${record.time}`;

      if (!lastAttendanceCheck[attendanceKey]) {
        lastAttendanceCheck[attendanceKey] = true;

        // Format time if it exists
        let timeStr = '';
        if (record.time) {
          if (record.time instanceof Date) {
            timeStr = record.time.toTimeString().slice(0, 5); // HH:MM format
          } else if (typeof record.time === 'string') {
            // Handle string time formats - extract HH:MM
            timeStr = record.time.split(':').slice(0, 2).join(':');
          }
        }

        const status = record.status?.trim().toUpperCase() || '';
        const dateStr = record.date instanceof Date 
          ? record.date.toISOString().split('T')[0]
          : record.date;

        // Get student name
        const firstName = record.first_name || '';
        const lastName = record.last_name || '';
        const studentName = `${firstName} ${lastName}`.trim();

        // Build message according to requirements:
        // "Attendance Update - Marked (Status) today at (time) (date)."
        let message = '';
        if (status === 'TIME-IN' || status === 'TIME-OUT') {
          // Format date nicely (e.g., "December 10, 2024")
          const dateObj = new Date(dateStr);
          const formattedDate = dateObj.toLocaleDateString('en-PH', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
          });
          
          // Check if it's today
          const today = new Date();
          const isToday = dateObj.toDateString() === today.toDateString();
          
          if (timeStr) {
            if (isToday) {
              message = `Marked ${status} today at ${timeStr}`;
            } else {
              message = `Marked ${status} at ${timeStr} on ${formattedDate}`;
            }
          } else {
            if (isToday) {
              message = `Marked ${status} today`;
            } else {
              message = `Marked ${status} on ${formattedDate}`;
            }
          }
        }

        // Only create notification if we have a valid status
        if (message && (status === 'TIME-IN' || status === 'TIME-OUT')) {
          const notificationTitle = 'Attendance Update';
          const fullMessage = message; // Store just the message, title is separate
          const year = record.year || null; // Get year from attendance record

          // Insert notification into notifications table
          // The table's id column doesn't have AUTO_INCREMENT, so we need to provide it manually
          try {
            // Get the maximum ID and increment it
            const [maxIdResult] = await pool.execute('SELECT MAX(id) as max_id FROM notifications');
            const nextId = (maxIdResult[0]?.max_id || 0) + 1;
            
            await pool.execute(
              'INSERT INTO notifications (id, student_id, type, title, message, date, year, time, `read`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
              [nextId, studentId, 'attendance', notificationTitle, fullMessage, dateStr, year, timeStr || null, 0]
            );
          } catch (insertError) {
            // If duplicate key error, try with a higher ID
            if (insertError.code === 'ER_DUP_ENTRY') {
              const [maxIdResult] = await pool.execute('SELECT MAX(id) as max_id FROM notifications');
              const nextId = (maxIdResult[0]?.max_id || 0) + 10; // Add buffer to avoid conflicts
              await pool.execute(
                'INSERT INTO notifications (id, student_id, type, title, message, date, year, time, `read`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [nextId, studentId, 'attendance', notificationTitle, fullMessage, dateStr, year, timeStr || null, 0]
              );
            } else {
              console.error('❌ Error inserting attendance notification:', insertError);
              throw insertError;
            }
          }

          // Get push token from student_push_tokens table
          const [tokenRows] = await pool.execute(
            'SELECT push_token FROM student_push_tokens WHERE student_id = ? LIMIT 1',
            [studentId]
          );

          // Send push notification via Socket.IO (if client is connected)
          io.to(`student_${studentId}`).emit('notification', {
            type: 'attendance',
            title: notificationTitle,
            message: message,
            date: dateStr,
          });

          if (tokenRows.length > 0) {
            console.log(`📤 Push notification sent to student ${studentId}: ${studentName} - ${status} (via Socket.IO)`);
            // Here you could also send to external push notification service (FCM, etc.)
            // using tokenRows[0].push_token
          } else {
            console.log(`⚠️  No push token found for student ${studentId}, notification saved but not pushed`);
          }
        }
      }
    }

    // Clean up old check records (keep last 1000 entries per type)
    if (Object.keys(lastPaymentCheck).length > 1000) {
      const keys = Object.keys(lastPaymentCheck);
      keys.slice(0, keys.length - 1000).forEach(key => delete lastPaymentCheck[key]);
    }
    if (Object.keys(lastAttendanceCheck).length > 1000) {
      const keys = Object.keys(lastAttendanceCheck);
      keys.slice(0, keys.length - 1000).forEach(key => delete lastAttendanceCheck[key]);
    }

  } catch (error) {
    console.error('❌ Error checking for new records:', error);
  }
}

// Run database monitoring every 30 seconds
setInterval(checkForNewRecords, 30000);
console.log('🔍 Database monitoring started (checking every 30 seconds)');

// Start server after a brief delay to allow connection test to complete
setTimeout(() => {
  server.listen(PORT, () => {
    console.log('='.repeat(50));
    console.log('🚀 KWAI Portal Backend Server Started!');
    console.log('='.repeat(50));
    console.log(`📡 Server running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 API Base URL: http://localhost:${PORT}`);
    console.log(`🔌 Socket.IO enabled`);
    console.log('='.repeat(50));
    console.log('📋 Available endpoints:');
    console.log('   POST   /api/auth/login');
    console.log('   POST   /api/auth/set-password');
    console.log('   POST   /api/push-token');
    console.log('   GET    /api/payments');
    console.log('   GET    /api/attendance');
    console.log('   GET    /api/notifications');
    console.log('   GET    /api/health');
    console.log('='.repeat(50));
  });
}, 500); // Wait 500ms for connection test to complete

