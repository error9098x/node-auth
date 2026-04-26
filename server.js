const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// Vulnerability 1: Weak bcrypt rounds
const SALT_ROUNDS = 1;

// Vulnerability 2: JWT with 'none' algorithm allowed
const JWT_SECRET = 'secret';

const users = [];

// Vulnerability 3: No input validation
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  
  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
  
  users.push({ username, password: hashedPassword });
  res.json({ message: 'User registered' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Vulnerable: allows 'none' algorithm
  const token = jwt.sign({ username }, JWT_SECRET, { algorithm: 'HS256' });
  res.json({ token });
});

app.listen(3000, () => {
  console.log('Auth server running on port 3000');
});
