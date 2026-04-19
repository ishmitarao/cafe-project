const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const db = new Database('cafe.db');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        dob TEXT,
        gender TEXT,
        address TEXT,
        country TEXT,
        city TEXT
    )
`);

app.post('/register', async (req, res) => {
    const { fullname, email, phone, password, dob, gender, address, country, city } = req.body;
    if (!fullname || !email || !phone || !password) {
        return res.json({ success: false, message: 'Please fill all required fields.' });
    }
    const existingEmail = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (existingEmail) {
        return res.json({ success: false, message: 'This email is already registered.' });
    }
    const existingPhone = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
    if (existingPhone) {
        return res.json({ success: false, message: 'This phone number is already registered.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    db.prepare('INSERT INTO users (fullname, email, phone, password, dob, gender, address, country, city) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(fullname, email, phone, hashedPassword, dob, gender, address, country, city);
    res.json({ success: true, message: 'Registration successful!' });
});

app.post('/login', async (req, res) => {
    const { emailOrPhone, password } = req.body;
    if (!emailOrPhone || !password) {
        return res.json({ success: false, message: 'Please enter your credentials.' });
    }
    const user = db.prepare('SELECT * FROM users WHERE email = ? OR phone = ?').get(emailOrPhone, emailOrPhone);
    if (!user) {
        return res.json({ success: false, message: 'No account found with this email or phone.' });
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
        return res.json({ success: false, message: 'Incorrect password.' });
    }
    res.json({ success: true, message: 'Login successful!', name: user.fullname });
});

app.listen(3000, () => {
    console.log('Server running at http://localhost:3000');
});
