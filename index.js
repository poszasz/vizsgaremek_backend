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

// adatbázis beáálítás
const db = mysql.createPool({
    host: 'localhost',
    port: '3306',
    user: 'root',
    password: '',
    database: 'project'
})

//APP
const app = express();

app.use(express.json())
app.use(cookieparser())
app.use(cors({
    origin: '*',
    credentials: true
}))


//Middleware
function auth(req, res, next) {
    const token = req.cookies[COOKIE_NAME]
    if (!token) {
        return res.status(409).json({ message: "You are not logged in." })
    } try {
        //tokenbol kinyerni a felhasznaloi adatokat
        req.user = jwt.verify(token, JWT_SECRET)
        next(); //haladhat tovabb a vegpontban
    } catch (error) {
        return res.status(410).json({ message: "Your session has expired." })
    }
}

//---------- VÉGPONTOK----------//


//regisztráció
app.post('/registration', async (req,res) =>{
    const {email,username, password} = req.body
    if (!email || !username || !password) {
        return res.status(400).json({message: "Missing data"})
    }
    try {
        //email validalas
        const isValid = await emailValidator(email)
        if(!isValid) {
            return res.status(401).json({message: "Email address is not valid."})
        }
        //username es email ellenorzese, hogy egyedi e
        const usernameEmailSQL = 'SELECT * FROM users WHERE email = ? OR username = ?'
        const [exists] = await db.query(usernameEmailSQL, [email,username])
        if(exists.length) {
            return res.status(402).json({message: "The username or email is already taken."})
        }
        //konkret regisztracio
        const hash = await bcrypt.hash(password,10)
        const registrationSQL = 'INSERT INTO users (email,username,password) VALUES (?,?,?)'
        const [result] = await db.query(registrationSQL, [email,username,hash])
        //valasz a felhasznalonak
        return res.status(200).json({message: "Registration successful!", id: result.insertId})
    } catch (error) {
        console.log(error)
        return res.status(500).json({message: "Server error!"})
    }
})

//belépés
app.post('/login', async (req,res) => {
    const {usernameOrEmail, password} =req.body
    if(!usernameOrEmail || !password) {
        return res.status(400).json({message: "Missing login data"})
    }
    try {
         //megadott fiokhoz milyen jelszo tartozik?
        const isvalid = await emailValidator(usernameOrEmail)
        let hashPassword = ""
        let user = {}
        if (isvalid) {
            //email + jelszót adott meg a belépéskor
            const sql = 'SELECT * FROM users WHERE email=?'
            const [rows] = await db.query(sql, [usernameOrEmail])
            if (rows.length) {
                user = rows[0]
                hashPassword= user.password
            } else {
                return res.status(402).json({message: "Incorrect email or password."})
            }
            //felhasználó + jelszót adott meg belépéskor
        } else {
            const sql = 'SELECT * FROM users WHERE username = ?'
            const [rows] = await db.query(sql, [usernameOrEmail])
            if (rows.length) {
                user = rows[0];
                hashPassword= user.password;
            } else {
                return res.status(402).json({message: "Incorrect email or password."})
            }
        }
        const ok = bcrypt.compare(password) //felh. vagy emailhez tartozo jelszo
        if (!ok) {
            return res.status(403).json({message: "Wrong password"})
        }
        const token = jwt.sign(
            { id: user.id, email: user.email, username: user.username },
            JWT_SECRET,
            {expiresIn: JWT_EXPIRES_IN}
        )
        res.cookie(COOKIE_NAME,token, COOKIE_OPTS)
        res.status(200).json({message: "login successful"})
    } catch (error) {
        console.log(error)
        return res.status(500).json({message: "Server error!"})
    } 
})

//VÉDETT 
app.post('/logout', auth, async (req, res) => {
    res.clearCookie(COOKIE_NAME, { path: '/' });
    res.status(200).json({ message: "logout successful" })
})

//VÉDETT
app.get('/adataim', auth, async (req, res) => {
    res.status(200).json(req.user)
})


//VÉDETT EMAIL
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
        sql1 = 'SELECT * FROM users WHERE email = ?'
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

//VÉDETT
app.put('/username', auth, async (req, res) => {
    const { newUsername } = req.body
    //megnezem, hogy megadta e body-ban az uj felhasznalonevet a felhasznalo
    if (!newUsername) {
        return res.status(401).json({ message: "Az új felhasználónév emgadása kötelező" })
    }
    try {
        //megnezem, hogy a felhasznalonev szerepel e a rendszerben
        sql1 = 'SELECT * FROM users WHERE users = ?'
        const [result] = await db.query(sql1, [newUsername])
        if (result.length) {
            return res.status(402).json({ message: "Ssername is already taken." })
        }
        //ha minden OK, modositom a felhasznalonevet
        const sql2 = 'UPDATE users SET username = ? WHERE id = ?'
        await db.query(sql2, [newUsername, req.user.id])
        return res.status(200).json({ message: "Username successfully updated." })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error" })
    }
})


app.delete('/account', auth, async (req, res) => {
    try {
        //toroljuk a felhasznalot
        const sql = 'DELETE FROM users WHERE id =?'
        await db.query(sql,[req.user.id])
        //utolso lepes
        res.clearCookie(COOKIE_NAME, { path: '/' })
        res.status(200).json({ message: "Successfuly deleted" })
    } catch (error) {
        console.log(error)
        res.status(500).json({message: "Server error"})
    }
})

//szerver inditasa
app.listen(PORT, HOST, () => {
    console.log(`API fut: http://${HOST}:${PORT}/`)
})