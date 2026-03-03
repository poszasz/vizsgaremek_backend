const express = require('express')
const cors = require('cors')
const cookieparser = require('cookie-parser')
const mysql = require('mysql2/promise')
const jwt = require('jsonwebtoken')
const emailValidator = require('node-email-verifier')
const bcrypt = require('bcrypt')

// config
const PORT = 3000;
const HOST = 'localhost'
const JWT_SECRET = 'valami_jelszo'
const JWT_EXPIRES_IN = '7d'
const COOKIE_NAME = 'auth-token'

// cookie beállítás
const COOKIE_OPTS = {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,
}

// adatbázis beállítás
const db = mysql.createPool({
    host: 'localhost',
    port: '3306',
    user: 'root',
    password: '',
    database: 'project'
})

// APP
const app = express();

app.use(express.json())
app.use(cookieparser())
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}))

// Middleware
function auth(req, res, next) {
    const token = req.cookies[COOKIE_NAME]
    if (!token) {
        return res.status(409).json({ message: "You are not logged in." })
    } 
    try {
        req.user = jwt.verify(token, JWT_SECRET)
        next();
    } catch (error) {
        return res.status(410).json({ message: "Your session has expired." })
    }
}

// ---------- VÉGPONTOK ----------

// REGISZTRÁCIÓ
app.post('/registration', async (req,res) =>{
    const {email, username, password} = req.body
    if (!email || !username || !password) {
        return res.status(400).json({message: "Missing data"})
    }
    try {
        const isValid = await emailValidator(email)
        if(!isValid) {
            return res.status(401).json({message: "Email address is not valid."})
        }
        
        const usernameEmailSQL = 'SELECT * FROM users WHERE email = ? OR username = ?'
        const [exists] = await db.query(usernameEmailSQL, [email, username])
        if(exists.length) {
            return res.status(402).json({message: "The username or email is already taken."})
        }
        
        const hash = await bcrypt.hash(password, 10)
        const registrationSQL = 'INSERT INTO users (email, username, password) VALUES (?, ?, ?)'
        const [result] = await db.query(registrationSQL, [email, username, hash])
        
        return res.status(200).json({message: "Registration successful!", id: result.insertId})
    } catch (error) {
        console.log(error)
        return res.status(500).json({message: "Server error!"})
    }
})

// BELÉPÉS
app.post('/login', async (req,res) => {
    const {usernameOrEmail, password} = req.body
    if(!usernameOrEmail || !password) {
        return res.status(400).json({message: "Missing login data"})
    }
    
    try {
        const isEmail = await emailValidator(usernameOrEmail)
        let user = {}
        
        if (isEmail) {
            const sql = 'SELECT * FROM users WHERE email = ?'
            const [rows] = await db.query(sql, [usernameOrEmail])
            if (rows.length === 0) {
                return res.status(402).json({message: "Incorrect email or password."})
            }
            user = rows[0]
        } else {
            const sql = 'SELECT * FROM users WHERE username = ?'
            const [rows] = await db.query(sql, [usernameOrEmail])
            if (rows.length === 0) {
                return res.status(402).json({message: "Incorrect email or password."})
            }
            user = rows[0]
        }
        
        const passwordMatch = await bcrypt.compare(password, user.password)
        if (!passwordMatch) {
            return res.status(403).json({message: "Wrong password"})
        }
        
        const token = jwt.sign(
            { id: user.id, email: user.email, username: user.username },
            JWT_SECRET,
            {expiresIn: JWT_EXPIRES_IN}
        )
        
        res.cookie(COOKIE_NAME, token, COOKIE_OPTS)
        
        res.status(200).json({ 
            message: "Login successful",
            user: {
                id: user.id,
                email: user.email,
                username: user.username
            }
        })
    } catch (error) {
        console.log(error)
        return res.status(500).json({message: "Server error!"})
    } 
})

// KIJELENTKEZÉS
app.post('/logout', auth, async (req, res) => {
    res.clearCookie(COOKIE_NAME, { path: '/' });
    res.status(200).json({ message: "Logout successful" })
})

// SAJÁT ADATOK
app.get('/adataim', auth, async (req, res) => {
    res.status(200).json(req.user)
})

// EMAIL MÓDOSÍTÁS
app.put('/email', auth, async (req, res) => {
    const { newEmail } = req.body
    if (!newEmail) {
        return res.status(401).json({ message: "Email is required." })
    }
    
    const isValid = await emailValidator(newEmail)
    if (!isValid) {
        return res.status(402).json({ message: "Enter a valid email." })
    }
    
    try {
        const sql1 = 'SELECT * FROM users WHERE email = ?'
        const [result] = await db.query(sql1, [newEmail])
        if (result.length) {
            return res.status(403).json({ message: "Email is already taken." })
        }
        
        const sql2 = 'UPDATE users SET email = ? WHERE id = ?'
        await db.query(sql2, [newEmail, req.user.id])
        return res.status(200).json({ message: "Email successfully updated." })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error!" })
    }
})

// FELHASZNÁLÓNÉV MÓDOSÍTÁS
app.put('/username', auth, async (req, res) => {
    const { newUsername } = req.body
    if (!newUsername) {
        return res.status(401).json({ message: "New username is required" })
    }
    
    try {
        const sql1 = 'SELECT * FROM users WHERE username = ?'
        const [result] = await db.query(sql1, [newUsername])
        if (result.length) {
            return res.status(402).json({ message: "Username is already taken." })
        }
        
        const sql2 = 'UPDATE users SET username = ? WHERE id = ?'
        await db.query(sql2, [newUsername, req.user.id])
        return res.status(200).json({ message: "Username successfully updated." })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error" })
    }
})

// JELSZÓ MÓDOSÍTÁS
app.put('/password', auth, async (req, res) => {
    const { nowPassword, newPassword } = req.body
    if (!nowPassword || !newPassword) {
        return res.status(400).json({ message: "Missing data" })
    }
    
    try {
        const sql = 'SELECT * FROM users WHERE id = ?'
        const [rows] = await db.query(sql, [req.user.id])
        const user = rows[0];
        const hashPassword = user.password;
        
        const passwordMatch = await bcrypt.compare(nowPassword, hashPassword)
        if(!passwordMatch) {
            return res.status(401).json({message: "Incorrect password."})
        } 
        
        const newHash = await bcrypt.hash(newPassword, 10);
        const sql2 = 'UPDATE users SET password = ? WHERE id = ?'
        await db.query(sql2, [newHash, req.user.id])
        res.status(200).json({ message: "New password set successfully." })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error" })
    }
})

// FELHASZNÁLÓ TÖRLÉSE
app.delete('/account', auth, async (req, res) => {
    try {
        const sql = 'DELETE FROM users WHERE id = ?'
        await db.query(sql, [req.user.id])
        res.clearCookie(COOKIE_NAME, { path: '/' })
        res.status(200).json({ message: "Account successfully deleted" })
    } catch (error) {
        console.log(error)
        res.status(500).json({message: "Server error"})
    }
})

// SAJÁT KÁRTYÁK LEKÉRÉSE
app.get('/my-cards', auth, async (req, res) => {
    try {
        const sql = `
            SELECT 
                user_cards.id,
                user_cards.acquired_at,
                cards.*
            FROM user_cards 
            INNER JOIN cards ON user_cards.card_id = cards.id 
            WHERE user_cards.user_id = ?
            ORDER BY cards.manufacturer, cards.name
        `
        const [rows] = await db.query(sql, [req.user.id])
        
        res.status(200).json({ 
            message: "Cards retrieved successfully",
            cards: rows 
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error!" })
    }
})


// SZERVER INDÍTÁSA
app.listen(PORT, HOST, () => {
    console.log(`API fut: http://${HOST}:${PORT}/`)
})