const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'my-secret-key'; // Use env var in real apps

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// In-memory storage (for testing)
let users = [];

// 🧑 CREATE USER
app.post('/create-user', async (req, res) => {
  const { username, password } = req.body;

  // Check if user already exists
  const existingUser = users.find(u => u.username === username);
  if (existingUser) return res.status(400).json({ message: 'User already exists' });

  // Hash password and store
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });

  res.status(201).json({ message: 'User created successfully' });
});

// 🔐 LOGIN USER
app.post('/login-user', async (req, res) => {
  const { username, password } = req.body;

  // Check if user exists
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });

  // Check password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

  // Create JWT token
  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

// ✅ VALIDATE TOKEN
app.get('/validate-user', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.json({ valid: false });

  const token = authHeader.split(' ')[1]; // Bearer <token>
  if (!token) return res.json({ valid: false });

  try {
    jwt.verify(token, SECRET_KEY);
    res.json({ valid: true });
  } catch (err) {
    res.json({ valid: false });
  }
});

// Start the server
app.listen(3000, () => {
    console.log('✅ Server running at http://localhost:3000');
  });