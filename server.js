require('dotenv').config();
const express = require('express');
const { AppUser } = require('./models');
const bcrypt = require('bcrypt'); // For hashing
const jwt = require('jsonwebtoken'); // For generating tokens
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Middleware to welcome users
app.get('/', (req, res) => {
  res.json("Welcome to secure password sharing");
});

// Hash a string using bcrypt
async function hashStr(str) {
  const saltRounds = 10; // Ensure this matches the salt rounds used during comparison
  return await bcrypt.hash(str, saltRounds);
}

// Create a new user
app.post('/users', async (req, res) => {
  try {
    const { firstName, lastName, email, password, encryption_key } = req.body;

    // Hash the password and encryption_key
    const hashedPassword = await hashStr(password);
    const hashedEncryptionKey = await hashStr(encryption_key);

    // Log the hashed password for debugging
    console.log('Hashed Password while inserting to DB:', hashedPassword);

    // Create the user with hashed values
    const user = await AppUser.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      encryption_key: hashedEncryptionKey
    });

    // Remove sensitive fields from the response
    const { password: hashedPasswordResponse, encryption_key: hashedEncryptionKeyResponse, ...safeUser } = user.toJSON();
    res.status(201).json(safeUser);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Login route
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find the user by email
    const user = await AppUser.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare the provided password with the hashed password
    const isMatch = await bcrypt.compare(password, user.password);

    // Log the comparison result for debugging
    console.log('Plain-text password:', password);
    console.log('Hashed password from DB:', user.password);
    console.log('Password match result:', isMatch);

    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate a JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email }, // Payload
      process.env.JWT_SECRET, // Secret key (store this in .env)
      { expiresIn: '1h' } // Token expiration time
    );

    // Remove sensitive fields from the response
    const { password: hashedPassword, encryption_key, ...safeUser } = user.toJSON();

    // Return the token along with the user data
    res.json({
      message: 'Login successful',
      user: safeUser,
      token // Include the token in the response
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all users
app.get('/users', async (req, res) => {
  try {
    const users = await AppUser.findAll();

    // Remove sensitive fields from the response
    const safeUsers = users.map(user => {
      const { password, encryption_key, ...safeUser } = user.toJSON();
      return safeUser;
    });

    res.json(safeUsers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});