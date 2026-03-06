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
app.post('/registration', async (req, res) => {
    const { email, username, password } = req.body
    if (!email || !username || !password) {
        return res.status(400).json({ message: "Missing data" })
    }
    
    const connection = await db.getConnection()
    
    try {
        await connection.beginTransaction()
        
        const isValid = await emailValidator(email)
        if (!isValid) {
            await connection.rollback()
            return res.status(401).json({ message: "Email address is not valid." })
        }

        const usernameEmailSQL = 'SELECT * FROM users WHERE email = ? OR username = ?'
        const [exists] = await connection.query(usernameEmailSQL, [email, username])
        if (exists.length) {
            await connection.rollback()
            return res.status(402).json({ message: "The username or email is already taken." })
        }

        const hash = await bcrypt.hash(password, 10)
        const registrationSQL = 'INSERT INTO users (email, username, password) VALUES (?, ?, ?)'
        const [result] = await connection.query(registrationSQL, [email, username, hash])
        
        const newUserId = result.insertId
        
        // 10 pack hozzáadása az új felhasználónak
        const packValues = []
        for (let i = 0; i < 10; i++) {
            packValues.push([newUserId])
        }
        
        await connection.query(
            'INSERT INTO user_packs (user_id) VALUES ?',
            [packValues]
        )
        
        await connection.commit()
        
        console.log(`New user registered: ${username} (ID: ${newUserId}) with 10 starter packs`)
        
        return res.status(200).json({ 
            message: "Registration successful! You received 10 starter packs.", 
            id: newUserId 
        })
        
    } catch (error) {
        await connection.rollback()
        console.log(error)
        return res.status(500).json({ message: "Server error!" })
    } finally {
        connection.release()
    }
})

// BELÉPÉS
app.post('/login', async (req, res) => {
    const { usernameOrEmail, password } = req.body
    if (!usernameOrEmail || !password) {
        return res.status(400).json({ message: "Missing login data" })
    }

    try {
        const isEmail = await emailValidator(usernameOrEmail)
        let user = {}

        if (isEmail) {
            const sql = 'SELECT * FROM users WHERE email = ?'
            const [rows] = await db.query(sql, [usernameOrEmail])
            if (rows.length === 0) {
                return res.status(402).json({ message: "Incorrect email or password." })
            }
            user = rows[0]
        } else {
            const sql = 'SELECT * FROM users WHERE username = ?'
            const [rows] = await db.query(sql, [usernameOrEmail])
            if (rows.length === 0) {
                return res.status(402).json({ message: "Incorrect email or password." })
            }
            user = rows[0]
        }

        const passwordMatch = await bcrypt.compare(password, user.password)
        if (!passwordMatch) {
            return res.status(403).json({ message: "Wrong password" })
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, username: user.username },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
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
        return res.status(500).json({ message: "Server error!" })
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
        if (!passwordMatch) {
            return res.status(401).json({ message: "Incorrect password." })
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
        res.status(500).json({ message: "Server error" })
    }
})

// SAJÁT KÁRTYÁK LEKÉRÉSE
app.get('/my-cards', auth, async (req, res) => {
    try {
        const sql = `
            SELECT 
                uc.id,
                uc.acquired_at,
                c.*,
                CASE WHEN ml.id IS NOT NULL THEN true ELSE false END as is_listed
            FROM user_cards uc
            INNER JOIN cards c ON uc.card_id = c.id
            LEFT JOIN market_listings ml ON uc.id = ml.user_card_id AND ml.status = 'active'
            WHERE uc.user_id = ?
            ORDER BY c.manufacturer, c.name
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

// ========== MARKET LISTINGOK LEKÉRÉSE ==========
app.get('/market-listings', auth, async (req, res) => {
    try {
        const sql = `
            SELECT 
                ml.id as listing_id,
                ml.status,
                uc.id as user_card_id,
                uc.acquired_at,
                c.*,
                u.id as seller_id,
                u.username as seller_username
            FROM market_listings ml
            INNER JOIN user_cards uc ON ml.user_card_id = uc.id
            INNER JOIN cards c ON uc.card_id = c.id
            INNER JOIN users u ON uc.user_id = u.id
            WHERE ml.status = 'active'
            ORDER BY ml.id DESC
        `
        const [rows] = await db.query(sql)

        res.status(200).json({
            message: "Market listings retrieved successfully",
            listings: rows
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error!", listings: [] })
    }
})

// ========== ÚJ LISTING LÉTREHOZÁSA ==========
app.post('/create-listing', auth, async (req, res) => {
    const { userCardId } = req.body

    if (!userCardId) {
        return res.status(400).json({ message: "Missing data" })
    }

    try {
        // Ellenőrizzük, hogy a kártya a felhasználóé-e
        const checkSql = 'SELECT * FROM user_cards WHERE id = ? AND user_id = ?'
        const [userCard] = await db.query(checkSql, [userCardId, req.user.id])

        if (userCard.length === 0) {
            return res.status(403).json({ message: "You don't own this card" })
        }

        // Ellenőrizzük, hogy nincs-e már aktív listingje
        const existingSql = 'SELECT * FROM market_listings WHERE user_card_id = ? AND status = "active"'
        const [existing] = await db.query(existingSql, [userCardId])

        if (existing.length > 0) {
            return res.status(400).json({ message: "This card is already listed" })
        }

        // Új listing létrehozása
        const insertSql = 'INSERT INTO market_listings (user_card_id, status) VALUES (?, "active")'
        const [result] = await db.query(insertSql, [userCardId])

        res.status(200).json({
            message: "Listing created successfully",
            listingId: result.insertId
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error!" })
    }
})

// ========== AJÁNLAT TÉTELE ==========
app.post('/make-offer', auth, async (req, res) => {
    const { listingId, offeredUserCardId } = req.body

    if (!listingId || !offeredUserCardId) {
        return res.status(400).json({ message: "Missing data" })
    }

    const connection = await db.getConnection()

    try {
        await connection.beginTransaction()

        // Ellenőrizzük, hogy a listing létezik-e és aktív-e
        const listingSql = 'SELECT * FROM market_listings WHERE id = ? AND status = "active"'
        const [listing] = await connection.query(listingSql, [listingId])

        if (listing.length === 0) {
            await connection.rollback()
            return res.status(404).json({ message: "Listing not found or not active" })
        }

        // Ellenőrizzük, hogy a felajánlott kártya a felhasználóé-e
        const cardSql = 'SELECT * FROM user_cards WHERE id = ? AND user_id = ?'
        const [userCard] = await connection.query(cardSql, [offeredUserCardId, req.user.id])

        if (userCard.length === 0) {
            await connection.rollback()
            return res.status(403).json({ message: "You don't own this card" })
        }

        // Ellenőrizzük, hogy nem a saját listingjére tesz-e ajánlatot
        const ownerSql = `
            SELECT uc.user_id 
            FROM market_listings ml
            INNER JOIN user_cards uc ON ml.user_card_id = uc.id
            WHERE ml.id = ?
        `
        const [owner] = await connection.query(ownerSql, [listingId])

        if (owner[0].user_id === req.user.id) {
            await connection.rollback()
            return res.status(400).json({ message: "You cannot offer on your own listing" })
        }

        // Ajánlat létrehozása
        const offerSql = 'INSERT INTO market_offers (listing_id, offered_user_card_id, status) VALUES (?, ?, "pending")'
        const [result] = await connection.query(offerSql, [listingId, offeredUserCardId])

        await connection.commit()

        res.status(200).json({
            message: "Offer created successfully",
            offerId: result.insertId
        })
    } catch (error) {
        await connection.rollback()
        console.log(error)
        res.status(500).json({ message: "Server error!" })
    } finally {
        connection.release()
    }
})

// ========== AJÁNLAT ELFOGADÁSA ==========
app.post('/accept-offer/:offerId', auth, async (req, res) => {
    const { offerId } = req.params

    const connection = await db.getConnection()

    try {
        await connection.beginTransaction()

        // Ajánlat lekérése
        const offerSql = `
            SELECT mo.*, ml.user_card_id as listing_card_id, uc.user_id as listing_owner_id
            FROM market_offers mo
            INNER JOIN market_listings ml ON mo.listing_id = ml.id
            INNER JOIN user_cards uc ON ml.user_card_id = uc.id
            WHERE mo.id = ? AND mo.status = "pending"
        `
        const [offer] = await connection.query(offerSql, [offerId])

        if (offer.length === 0) {
            await connection.rollback()
            return res.status(404).json({ message: "Offer not found" })
        }

        // Ellenőrizzük, hogy a bejelentkezett felhasználó a listing tulajdonosa-e
        if (offer[0].listing_owner_id !== req.user.id) {
            await connection.rollback()
            return res.status(403).json({ message: "You are not the owner of this listing" })
        }

        // Kártyák cseréje
        // 1. A listing kártya átmegy az ajánlattevőhöz
        await connection.query(
            'UPDATE user_cards SET user_id = (SELECT user_id FROM market_offers WHERE id = ?) WHERE id = ?',
            [offerId, offer[0].listing_card_id]
        )

        // 2. Az ajánlott kártya átmegy a listing tulajdonosához
        await connection.query(
            'UPDATE user_cards SET user_id = ? WHERE id = ?',
            [req.user.id, offer[0].offered_user_card_id]
        )

        // Listing státusz frissítése
        await connection.query(
            'UPDATE market_listings SET status = "traded" WHERE id = ?',
            [offer[0].listing_id]
        )

        // Ajánlat státusz frissítése
        await connection.query(
            'UPDATE market_offers SET status = "accepted" WHERE id = ?',
            [offerId]
        )

        // Többi függőben lévő ajánlat elutasítása
        await connection.query(
            'UPDATE market_offers SET status = "rejected" WHERE listing_id = ? AND id != ? AND status = "pending"',
            [offer[0].listing_id, offerId]
        )

        await connection.commit()

        res.status(200).json({ message: "Offer accepted successfully" })
    } catch (error) {
        await connection.rollback()
        console.log(error)
        res.status(500).json({ message: "Server error!" })
    } finally {
        connection.release()
    }
})

// ========== SAJÁT LISTINGEK LEKÉRÉSE ==========
app.get('/my-listings', auth, async (req, res) => {
    try {
        const sql = `
            SELECT 
                ml.id as listing_id,
                ml.status,
                uc.id as user_card_id,
                uc.acquired_at,
                c.*
            FROM market_listings ml
            INNER JOIN user_cards uc ON ml.user_card_id = uc.id
            INNER JOIN cards c ON uc.card_id = c.id
            WHERE uc.user_id = ?
            ORDER BY ml.id DESC
        `
        const [rows] = await db.query(sql, [req.user.id])

        res.status(200).json({
            message: "My listings retrieved successfully",
            listings: rows
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error!", listings: [] })
    }
})

// ========== LISTING TÖRLÉSE ==========
app.delete('/listing/:listingId', auth, async (req, res) => {
    const { listingId } = req.params

    try {
        // Ellenőrizzük, hogy a listing a felhasználóé-e
        const checkSql = `
            SELECT ml.* 
            FROM market_listings ml
            INNER JOIN user_cards uc ON ml.user_card_id = uc.id
            WHERE ml.id = ? AND uc.user_id = ?
        `
        const [listing] = await db.query(checkSql, [listingId, req.user.id])

        if (listing.length === 0) {
            return res.status(403).json({ message: "You don't own this listing" })
        }

        // Listing törlése (vagy státusz frissítése)
        await db.query('UPDATE market_listings SET status = "cancelled" WHERE id = ?', [listingId])

        res.status(200).json({ message: "Listing cancelled successfully" })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error!" })
    }
})

// ========== PACKOK LEKÉRÉSE ==========
app.get('/my-packs', auth, async (req, res) => {
    try {
        // Ellenőrizzük, hogy van-e user_packs tábla
        const [tableCheck] = await db.query("SHOW TABLES LIKE 'user_packs'")
        
        if (tableCheck.length > 0) {
            // Ha van user_packs tábla, abból számoljuk
            const [rows] = await db.query(
                'SELECT COUNT(*) as pack_count FROM user_packs WHERE user_id = ?',
                [req.user.id]
            )
            console.log(`User ${req.user.id} has ${rows[0].pack_count} packs`)
            return res.status(200).json({ 
                message: "Packs retrieved successfully",
                packs: rows[0].pack_count || 0
            })
        } else {
            return res.status(200).json({ 
                message: "Packs retrieved successfully",
                packs: 0
            })
        }
    } catch (error) {
        console.error("Error in /my-packs:", error)
        res.status(500).json({ message: "Server error!", packs: 0 })
    }
})

// ========== PACKOK LEKÉRÉSE ==========
app.get('/my-packs', auth, async (req, res) => {
    try {
        // Ellenőrizzük, hogy van-e user_packs tábla
        const [tableCheck] = await db.query("SHOW TABLES LIKE 'user_packs'")
        
        if (tableCheck.length > 0) {
            // Ha van user_packs tábla, abból számoljuk
            const [rows] = await db.query(
                'SELECT COUNT(*) as pack_count FROM user_packs WHERE user_id = ?',
                [req.user.id]
            )
            console.log(`User ${req.user.id} has ${rows[0].pack_count} packs`)
            return res.status(200).json({ 
                message: "Packs retrieved successfully",
                packs: rows[0].pack_count || 0
            })
        } else {
            return res.status(200).json({ 
                message: "Packs retrieved successfully",
                packs: 0
            })
        }
    } catch (error) {
        console.error("Error in /my-packs:", error)
        res.status(500).json({ message: "Server error!", packs: 0 })
    }
})

// ========== PACK NYITÁS ==========
app.post('/open-pack', auth, async (req, res) => {
    const connection = await db.getConnection()
    
    try {
        await connection.beginTransaction()
        
        // 1. Ellenőrizzük, hogy van-e packja
        const [packRows] = await connection.query(
            'SELECT id FROM user_packs WHERE user_id = ? LIMIT 1',
            [req.user.id]
        )
        
        if (packRows.length === 0) {
            await connection.rollback()
            return res.status(400).json({ message: "You don't have any packs to open!" })
        }
        
        // 2. Válassz egy random kártyát (kivéve a teszt kártyákat 1-4)
        const [cards] = await connection.query(
            'SELECT * FROM cards WHERE id > 4 ORDER BY RAND() LIMIT 1'
        )
        
        if (cards.length === 0) {
            await connection.rollback()
            return res.status(404).json({ message: "No cards available in the database" })
        }
        
        const selectedCard = cards[0]
        
        // 3. Add hozzá a user_cards táblához
        await connection.query(
            'INSERT INTO user_cards (user_id, card_id, acquired_at) VALUES (?, ?, NOW())',
            [req.user.id, selectedCard.id]
        )
        
        // 4. Töröld a felhasznált packot
        await connection.query(
            'DELETE FROM user_packs WHERE id = ?',
            [packRows[0].id]
        )
        
        await connection.commit()
        
        console.log(`User ${req.user.id} opened a pack and got: ${selectedCard.manufacturer} ${selectedCard.name}`)
        
        // 5. Válasz küldése (típus nélkül)
        res.status(200).json({ 
            message: "Pack opened successfully!",
            card: {
                id: selectedCard.id,
                card_name: selectedCard.name,
                manufacturer: selectedCard.manufacturer,
                horsepower: selectedCard.horsepower,
                acceleration: selectedCard.acceleration,
                fuel: selectedCard.fuel,
                image_url: selectedCard.image_url
            }
        })
        
    } catch (error) {
        await connection.rollback()
        console.error("Error in /open-pack:", error)
        res.status(500).json({ message: "Server error during pack opening!" })
    } finally {
        connection.release()
    }
})


// SZERVER INDÍTÁSA
app.listen(PORT, HOST, () => {
    console.log(`API fut: http://${HOST}:${PORT}/`)
})