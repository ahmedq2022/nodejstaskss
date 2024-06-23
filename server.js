const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const PORT = 4000; // Use port 4000 for Express backend
const SECRET_KEY = 'your-jwt-secret-key';

let users = [];

app.use(bodyParser.json());
app.use(cors());
app.use(session({
    secret: 'your-session-secret',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60000 } // 1 minute
}));

// Endpoint to register a new user
app.post('/auth/register', async (req, res) => {
    const { username, password } = req.body;

    // Check if user already exists
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ message: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 8);

    // Store the user in memory (for demo purposes)
    users.push({ username, password: hashedPassword });

    // Return success response
    res.json({ username });
});

// Endpoint to handle user login
app.post('/auth/login', async (req, res) => {
    const { username, password, rememberMe } = req.body;
    const user = users.find(u => u.username === username);

    // Check if user exists
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });

    // Store user session if rememberMe is checked
    if (rememberMe) {
        req.session.user = user;
    }

    // Return user and token
    res.json({ user, token });
});

// Endpoint to handle user logout
app.post('/auth/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ message: 'Could not log out' });
        }
        res.json({ message: 'Logged out' });
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
