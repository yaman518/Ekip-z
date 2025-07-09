const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../config/database');
const { body, validationResult } = require('express-validator');

const router = express.Router();

// Input validation middleware
const validateRegister = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Geçerli bir email adresi girin'),
    body('password')
        .isLength({ min: 8 })
        .withMessage('Şifre en az 8 karakter olmalıdır')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .withMessage('Şifre en az bir büyük harf, bir küçük harf ve bir rakam içermelidir'),
    body('firstName')
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('Ad 2-50 karakter arasında olmalıdır'),
    body('lastName')
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('Soyad 2-50 karakter arasında olmalıdır'),
    body('username')
        .trim()
        .isLength({ min: 3, max: 30 })
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('Kullanıcı adı 3-30 karakter arasında, sadece harf, rakam ve alt çizgi içermelidir')
];

const validateLogin = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Geçerli bir email adresi girin'),
    body('password')
        .notEmpty()
        .withMessage('Şifre gereklidir')
];

// Register endpoint
router.post('/register', validateRegister, async (req, res) => {
    try {
        // Validation errors check
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                message: 'Girilen bilgiler geçersiz',
                errors: errors.array() 
            });
        }

        const { email, password, firstName, lastName, username, phone, city } = req.body;
        
        // Check if user already exists
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE email = $1 OR username = $2',
            [email, username]
        );
        
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ 
                message: 'Bu email veya kullanıcı adı zaten kullanılıyor' 
            });
        }
        
        // Hash password
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Create user
        const result = await pool.query(
            `INSERT INTO users (email, password_hash, first_name, last_name, username, phone, city) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) 
             RETURNING id, email, username, first_name, last_name`,
            [email, hashedPassword, firstName, lastName, username, phone, city]
        );
        
        const user = result.rows[0];
        
        // Generate JWT token
        const token = jwt.sign(
            { 
                userId: user.id, 
                email: user.email,
                username: user.username 
            },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.status(201).json({
            message: 'Kullanıcı başarıyla oluşturuldu',
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                firstName: user.first_name,
                lastName: user.last_name
            },
            token
        });
        
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ message: 'Sunucu hatası' });
    }
});

// Login endpoint
router.post('/login', validateLogin, async (req, res) => {
    try {
        // Validation errors check
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                message: 'Girilen bilgiler geçersiz',
                errors: errors.array() 
            });
        }

        const { email, password } = req.body;
        
        // Find user
        const result = await pool.query(
            `SELECT id, email, password_hash, username, first_name, last_name, 
                    profile_image, is_verified, created_at 
             FROM users WHERE email = $1`,
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ 
                message: 'Geçersiz email veya şifre' 
            });
        }
        
        const user = result.rows[0];
        
        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!isValidPassword) {
            return res.status(401).json({ 
                message: 'Geçersiz email veya şifre' 
            });
        }
        
        // Generate JWT token
        const token = jwt.sign(
            { 
                userId: user.id, 
                email: user.email,
                username: user.username 
            },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            message: 'Giriş başarılı',
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                firstName: user.first_name,
                lastName: user.last_name,
                profileImage: user.profile_image,
                isVerified: user.is_verified,
                createdAt: user.created_at
            },
            token
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Sunucu hatası' });
    }
});

// Get current user
router.get('/me', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, email, username, first_name, last_name, phone, city, 
                    bio, profile_image, skills, portfolio_url, github_url, 
                    linkedin_url, rating, total_reviews, is_verified, created_at 
             FROM users WHERE id = $1`,
            [req.user.userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Kullanıcı bulunamadı' });
        }
        
        const user = result.rows[0];
        res.json({
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                firstName: user.first_name,
                lastName: user.last_name,
                phone: user.phone,
                city: user.city,
                bio: user.bio,
                profileImage: user.profile_image,
                skills: user.skills || [],
                portfolioUrl: user.portfolio_url,
                githubUrl: user.github_url,
                linkedinUrl: user.linkedin_url,
                rating: user.rating,
                totalReviews: user.total_reviews,
                isVerified: user.is_verified,
                createdAt: user.created_at
            }
        });
        
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ message: 'Sunucu hatası' });
    }
});

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Erişim token gerekli' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Geçersiz token' });
        }
        req.user = user;
        next();
    });
}

module.exports = router;