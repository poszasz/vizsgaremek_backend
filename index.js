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
<<<<<<< HEAD
        return res.status(401).json({ message: "You are not logged in." })
=======
        return res.status(409).json({ message: "You are not logged in." })
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
    }
    try {
        req.user = jwt.verify(token, JWT_SECRET)
        next();
    } catch (error) {
<<<<<<< HEAD
        return res.status(401).json({ message: "Your session has expired." })
=======
        return res.status(410).json({ message: "Your session has expired." })
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
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
<<<<<<< HEAD
            return res.status(400).json({ message: "Email address is not valid." })
=======
            return res.status(401).json({ message: "Email address is not valid." })
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
        }

        const usernameEmailSQL = 'SELECT * FROM users WHERE email = ? OR username = ?'
        const [exists] = await connection.query(usernameEmailSQL, [email, username])
        if (exists.length) {
            await connection.rollback()
<<<<<<< HEAD
            return res.status(409).json({ message: "The username or email is already taken." })
=======
            return res.status(402).json({ message: "The username or email is already taken." })
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
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
<<<<<<< HEAD
                return res.status(401).json({ message: "Incorrect email or password." })
=======
                return res.status(402).json({ message: "Incorrect email or password." })
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
            }
            user = rows[0]
        } else {
            const sql = 'SELECT * FROM users WHERE username = ?'
            const [rows] = await db.query(sql, [usernameOrEmail])
            if (rows.length === 0) {
<<<<<<< HEAD
                return res.status(401).json({ message: "Incorrect email or password." })
=======
                return res.status(402).json({ message: "Incorrect email or password." })
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
            }
            user = rows[0]
        }

        const passwordMatch = await bcrypt.compare(password, user.password)
        if (!passwordMatch) {
<<<<<<< HEAD
            return res.status(401).json({ message: "Wrong password" })
=======
            return res.status(403).json({ message: "Wrong password" })
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
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

<<<<<<< HEAD
/// SAJÁT KÁRTYÁK LEKÉRÉSE (JAVÍTVA)
=======
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

// SAJÁT KÁRTYÁK LEKÉRÉSE (módosított)
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
app.get('/my-cards', auth, async (req, res) => {
    try {
        const sql = `
            SELECT 
<<<<<<< HEAD
                uc.id as user_card_id,  -- Ez a user_cards.id (1,2,3,4)
                uc.card_id,              -- Ez a cards.id (25,35,36,41)
=======
                uc.id,
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
                uc.acquired_at,
                c.*,
                CASE WHEN ml.id IS NOT NULL AND ml.status = 'active' THEN true ELSE false END as is_listed,
                CASE WHEN mo.id IS NOT NULL AND mo.status = 'pending' THEN true ELSE false END as is_offered
            FROM user_cards uc
            INNER JOIN cards c ON uc.card_id = c.id
            LEFT JOIN market_listings ml ON uc.id = ml.user_card_id AND ml.status = 'active'
            LEFT JOIN market_offers mo ON uc.id = mo.offered_user_card_id AND mo.status = 'pending'
            WHERE uc.user_id = ?
            ORDER BY c.manufacturer, c.name
        `
        const [rows] = await db.query(sql, [req.user.id])
<<<<<<< HEAD
        
        console.log("===== BACKEND VÁLASZ (JAVÍTVA) =====");
        console.log(rows);
        console.log("==========================");
        
=======

>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
        res.status(200).json({
            message: "Cards retrieved successfully",
            cards: rows
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error!" })
    }
})

<<<<<<< HEAD
// MARKET LISTINGOK LEKÉRÉSE
=======
// ========== MARKET LISTINGOK LEKÉRÉSE ==========
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
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

<<<<<<< HEAD
// ÚJ LISTING LÉTREHOZÁSA (DEBUG VERZIÓ)
app.post('/create-listing', auth, async (req, res) => {
    const { userCardId } = req.body
    
    // DEBUG
    console.log("========== CREATE LISTING DEBUG ==========");
    console.log("1. Kapott userCardId:", userCardId);
    console.log("2. Kapott userCardId típusa:", typeof userCardId);
    console.log("3. Bejelentkezett user ID a tokenből:", req.user.id);
    console.log("4. Teljes req.user objektum:", req.user);

    if (!userCardId) {
        console.log("5. HIBA: Hiányzó userCardId");
        return res.status(400).json({ message: "Missing data" })
    }

    const connection = await db.getConnection()

    try {
        await connection.beginTransaction()

        // Először nézzük meg a kártyát user_id nélkül
        const checkAnySql = 'SELECT * FROM user_cards WHERE id = ?'
        console.log("6. SQL lekérdezés (user_id nélkül):", checkAnySql, [userCardId]);
        const [anyCard] = await connection.query(checkAnySql, [userCardId])
        console.log("7. Eredmény sorok száma:", anyCard.length);
        
        if (anyCard.length > 0) {
            console.log("8. Kártya adatai:", anyCard[0]);
            console.log("9. Kártya user_id-ja az adatbázisban:", anyCard[0].user_id);
            console.log("10. Összehasonlítás:", anyCard[0].user_id, "vs", req.user.id);
            console.log("11. Egyezik?", anyCard[0].user_id === req.user.id);
        } else {
            console.log("12. A kártya NEM létezik az adatbázisban!");
        }

        // Ellenőrizzük, hogy a kártya a felhasználóé-e
        const checkSql = 'SELECT * FROM user_cards WHERE id = ? AND user_id = ?'
        console.log("13. SQL lekérdezés (AND feltétellel):", checkSql, [userCardId, req.user.id]);
        const [userCard] = await connection.query(checkSql, [userCardId, req.user.id])
        console.log("14. Találatok száma AND feltétellel:", userCard.length);

        if (userCard.length === 0) {
            await connection.rollback()
            console.log("15. HIBA: A kártya nem a felhasználóé!");
=======
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
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
            return res.status(403).json({ message: "You don't own this card" })
        }

        // Ellenőrizzük, hogy nincs-e már aktív listingje
        const existingSql = 'SELECT * FROM market_listings WHERE user_card_id = ? AND status = "active"'
<<<<<<< HEAD
        const [existing] = await connection.query(existingSql, [userCardId])

        if (existing.length > 0) {
            await connection.rollback()
            console.log("16. HIBA: A kártya már listingelve van");
            return res.status(400).json({ message: "This card is already listed" })
        }

        // Ellenőrizzük, hogy nincs-e függőben lévő offer a kártyára
        const offerSql = 'SELECT * FROM market_offers WHERE offered_user_card_id = ? AND status = "pending"'
        const [offers] = await connection.query(offerSql, [userCardId])

        if (offers.length > 0) {
            await connection.rollback()
            console.log("17. HIBA: A kártyának vannak függőben lévő offerjei");
            return res.status(400).json({ message: "This card has pending offers" })
        }

        // Új listing létrehozása
        const insertSql = 'INSERT INTO market_listings (user_card_id, status) VALUES (?, "active")'
        const [result] = await connection.query(insertSql, [userCardId])

        await connection.commit()
        console.log("18. SIKER! Listing létrehozva, ID:", result.insertId);
=======
        const [existing] = await db.query(existingSql, [userCardId])

        if (existing.length > 0) {
            return res.status(400).json({ message: "This card is already listed" })
        }

        // Új listing létrehozása
        const insertSql = 'INSERT INTO market_listings (user_card_id, status) VALUES (?, "active")'
        const [result] = await db.query(insertSql, [userCardId])
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e

        res.status(200).json({
            message: "Listing created successfully",
            listingId: result.insertId
        })
    } catch (error) {
<<<<<<< HEAD
        await connection.rollback()
        console.log("19. HIBA a tranzakcióban:", error);
        res.status(500).json({ message: "Server error!" })
    } finally {
        connection.release()
    }
})

// AJÁNLAT TÉTELE
=======
        console.log(error)
        res.status(500).json({ message: "Server error!" })
    }
})

// ========== AJÁNLAT TÉTELE ==========
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
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

<<<<<<< HEAD
        // Ellenőrizzük, hogy a felajánlott kártyának nincs-e már aktív listingje
        const cardListingSql = 'SELECT * FROM market_listings WHERE user_card_id = ? AND status = "active"'
        const [cardListing] = await connection.query(cardListingSql, [offeredUserCardId])

        if (cardListing.length > 0) {
            await connection.rollback()
            return res.status(400).json({ message: "This card is already listed" })
        }

        // Ellenőrizzük, hogy a felajánlott kártyának nincs-e már függőben lévő offerje
        const cardOfferSql = 'SELECT * FROM market_offers WHERE offered_user_card_id = ? AND status = "pending"'
        const [cardOffer] = await connection.query(cardOfferSql, [offeredUserCardId])

        if (cardOffer.length > 0) {
            await connection.rollback()
            return res.status(400).json({ message: "This card already has a pending offer" })
        }

        // Ajánlat létrehozása
        const offerSql = 'INSERT INTO market_offers (listing_id, offered_user_card_id, status, created_at) VALUES (?, ?, "pending", NOW())'
=======
        // Ajánlat létrehozása
        const offerSql = 'INSERT INTO market_offers (listing_id, offered_user_card_id, status) VALUES (?, ?, "pending")'
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
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

<<<<<<< HEAD
// SAJÁT FÜGGŐBEN LÉVŐ OFFEREK LEKÉRÉSE
=======
// ========== SAJÁT FÜGGŐBEN LÉVŐ OFFEREK LEKÉRÉSE ==========
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
app.get('/my-pending-offers', auth, async (req, res) => {
    try {
        const sql = `
            SELECT 
                mo.id as offer_id,
                mo.offered_user_card_id,
                mo.status,
                mo.created_at,
                ml.id as listing_id,
                c.manufacturer,
                c.name,
<<<<<<< HEAD
                c.horsepower,
                c.acceleration,
                c.fuel,
                c.image_url
=======
                c.horsepower
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
            FROM market_offers mo
            INNER JOIN market_listings ml ON mo.listing_id = ml.id
            INNER JOIN user_cards uc ON mo.offered_user_card_id = uc.id
            INNER JOIN cards c ON uc.card_id = c.id
            WHERE uc.user_id = ? AND mo.status = 'pending'
            ORDER BY mo.created_at DESC
        `
        const [rows] = await db.query(sql, [req.user.id])

        res.status(200).json({
            message: "Pending offers retrieved successfully",
            offers: rows
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error!", offers: [] })
    }
})

<<<<<<< HEAD
// AJÁNLAT ELFOGADÁSA
=======
// ========== AJÁNLAT ELFOGADÁSA ==========
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
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

<<<<<<< HEAD
// SAJÁT LISTINGEK LEKÉRÉSE
=======
// ========== SAJÁT LISTINGEK LEKÉRÉSE ==========
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
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

<<<<<<< HEAD
// LISTING TÖRLÉSE (CANCELLED státusz)
app.delete('/listing/:listingId', auth, async (req, res) => {
    const { listingId } = req.params

    const connection = await db.getConnection()

    try {
        await connection.beginTransaction()

        // Ellenőrizzük, hogy a listing a felhasználóé-e
=======
// ========== LISTING TÖRLÉSE ==========
app.delete('/listing/:listingId', auth, async (req, res) => {
    const { listingId } = req.params

    try {
        // Ellenőrizzük, hogy a listing a felhasználóé-e ÉS lekérjük a user_card_id-t
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
        const checkSql = `
            SELECT ml.*, uc.id as user_card_id
            FROM market_listings ml
            INNER JOIN user_cards uc ON ml.user_card_id = uc.id
            WHERE ml.id = ? AND uc.user_id = ?
        `
<<<<<<< HEAD
        const [listing] = await connection.query(checkSql, [listingId, req.user.id])

        if (listing.length === 0) {
            await connection.rollback()
            return res.status(403).json({ message: "You don't own this listing" })
        }

        // Csak aktív listinget lehet törölni
        if (listing[0].status !== 'active') {
            await connection.rollback()
            return res.status(400).json({ message: "Only active listings can be deleted" })
        }

        // Listing törlése (státusz frissítése cancelled-re)
        await connection.query('UPDATE market_listings SET status = "cancelled" WHERE id = ?', [listingId])

        // A hozzá tartozó függőben lévő offerek státuszának frissítése
        await connection.query(
            'UPDATE market_offers SET status = "rejected" WHERE listing_id = ? AND status = "pending"',
            [listingId]
        )

        // Ha a kártyának voltak saját offerjei (ahol ő ajánlotta fel), azokat is elutasítjuk
        await connection.query(
            'UPDATE market_offers SET status = "rejected" WHERE offered_user_card_id = ? AND status = "pending"',
            [listing[0].user_card_id]
        )

        await connection.commit()

        res.status(200).json({ message: "Listing cancelled successfully" })
    } catch (error) {
        await connection.rollback()
        console.log(error)
        res.status(500).json({ message: "Server error!" })
    } finally {
        connection.release()
    }
})

// OFFER TÖRLÉSE
app.delete('/offer/:offerId', auth, async (req, res) => {
    const { offerId } = req.params

    try {
        // Ellenőrizzük, hogy az offer a felhasználóé-e (ő ajánlotta fel a kártyáját)
        const checkSql = `
            SELECT mo.*, uc.user_id as offer_owner_id
            FROM market_offers mo
            INNER JOIN user_cards uc ON mo.offered_user_card_id = uc.id
            WHERE mo.id = ?
        `
        const [offer] = await db.query(checkSql, [offerId])

        if (offer.length === 0) {
            return res.status(404).json({ message: "Offer not found" })
        }

        // Ellenőrizzük, hogy a bejelentkezett felhasználó a tulajdonosa-e az offernek
        if (offer[0].offer_owner_id !== req.user.id) {
            return res.status(403).json({ message: "You don't own this offer" })
        }

        // Csak pending státuszú offert lehet törölni
        if (offer[0].status !== 'pending') {
            return res.status(400).json({ message: "Only pending offers can be deleted" })
        }

        // Offer törlése (státusz frissítése rejected-re)
        await db.query('UPDATE market_offers SET status = "rejected" WHERE id = ?', [offerId])

        res.status(200).json({ message: "Offer cancelled successfully" })
    } catch (error) {
=======
        const [listing] = await db.query(checkSql, [listingId, req.user.id])

        if (listing.length === 0) {
            return res.status(403).json({ message: "You don't own this listing" })
        }

        // Listing törlése (státusz frissítése cancelled-re)
        await db.query('UPDATE market_listings SET status = "cancelled" WHERE id = ?', [listingId])

        // A hozzá tartozó függőben lévő offerek státuszának frissítése
        await db.query('UPDATE market_offers SET status = "rejected" WHERE listing_id = ? AND status = "pending"', [listingId])

        // Ha a kártyának voltak saját offerjei (ahol ő ajánlotta fel), azokat is elutasítjuk
        await db.query(`
            UPDATE market_offers 
            SET status = 'rejected' 
            WHERE offered_user_card_id = ? AND status = 'pending'
        `, [listing[0].user_card_id])

        res.status(200).json({ message: "Listing cancelled successfully" })
    } catch (error) {
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
        console.log(error)
        res.status(500).json({ message: "Server error!" })
    }
})

<<<<<<< HEAD
// PACKOK LEKÉRÉSE (JAVÍTVA - duplikáció eltávolítva)
app.get('/my-packs', auth, async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT COUNT(*) as pack_count FROM user_packs WHERE user_id = ?',
            [req.user.id]
        )
        console.log(`User ${req.user.id} has ${rows[0].pack_count} packs`)
        return res.status(200).json({ 
            message: "Packs retrieved successfully",
            packs: rows[0].pack_count || 0
        })
=======
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
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
    } catch (error) {
        console.error("Error in /my-packs:", error)
        res.status(500).json({ message: "Server error!", packs: 0 })
    }
})

<<<<<<< HEAD
// PACK NYITÁS
=======
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
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
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
        
<<<<<<< HEAD
=======
        // 5. Válasz küldése (típus nélkül)
>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
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

<<<<<<< HEAD
=======
// ========== OFFER TÖRLÉSE ==========
app.delete('/offer/:offerId', auth, async (req, res) => {
    const { offerId } = req.params

    try {
        // Ellenőrizzük, hogy az offer a felhasználóé-e (ő ajánlotta fel a kártyáját)
        const checkSql = `
            SELECT mo.*, uc.user_id as offer_owner_id
            FROM market_offers mo
            INNER JOIN user_cards uc ON mo.offered_user_card_id = uc.id
            WHERE mo.id = ?
        `
        const [offer] = await db.query(checkSql, [offerId])

        if (offer.length === 0) {
            return res.status(404).json({ message: "Offer not found" })
        }

        // Ellenőrizzük, hogy a bejelentkezett felhasználó a tulajdonosa-e az offernek
        if (offer[0].offer_owner_id !== req.user.id) {
            return res.status(403).json({ message: "You don't own this offer" })
        }

        // Csak pending státuszú offert lehet törölni
        if (offer[0].status !== 'pending') {
            return res.status(400).json({ message: "Only pending offers can be deleted" })
        }

        // Offer törlése (státusz frissítése cancelled-re)
        await db.query('UPDATE market_offers SET status = "rejected" WHERE id = ?', [offerId])

        res.status(200).json({ message: "Offer cancelled successfully" })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error!" })
    }
})


// ========== LISTING TÖRLÉSE (MÁR LÉTEZIK, DE BIZTOS) ==========
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

        // Listing törlése (státusz frissítése cancelled-re)
        await db.query('UPDATE market_listings SET status = "cancelled" WHERE id = ?', [listingId])

        // Opcionális: A hozzá tartozó függőben lévő offerek státuszának frissítése
        await db.query('UPDATE market_offers SET status = "rejected" WHERE listing_id = ? AND status = "pending"', [listingId])

        res.status(200).json({ message: "Listing cancelled successfully" })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error!" })
    }
})


>>>>>>> 994bd3400db3c84195b2512797967f26f108f68e
// SZERVER INDÍTÁSA
app.listen(PORT, HOST, () => {
    console.log(`API fut: http://${HOST}:${PORT}/`)
})