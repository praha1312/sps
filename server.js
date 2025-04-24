require('dotenv').config();
const express = require('express');
const { AppUser, UserPassword } = require('./models'); // Import models
const bcrypt = require('bcrypt'); // For hashing
const jwt = require('jsonwebtoken'); // For generating tokens
const crypto = require('crypto'); // For encryption/decryption

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

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token.' });
    req.auth = user;
    next();
  });
}

// Helper functions for encryption and decryption
function encrypt(text, key) {
  const cipher = crypto.createCipher('aes-256-cbc', key);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decrypt(encryptedText, key) {
  const decipher = crypto.createDecipher('aes-256-cbc', key);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
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

// Save a password
app.post('/passwords/save', authenticateToken, async (req, res) => {
  try {
    const { url, username, password, encryption_key, label } = req.body;
    const userId = req.auth.userId;

    // Validate input
    if (!(url && username && password && encryption_key)) {
      return res.status(400).json({ message: 'Missing parameters' });
    }

    // Find the user and verify the encryption key
    const userRecord = await AppUser.findOne({
      attributes: ['encryption_key'],
      where: { id: userId },
    });
    if (!userRecord) {
      return res.status(403).json({ message: 'Unable to find the account' });
    }
    const matched = await bcrypt.compare(encryption_key, userRecord.encryption_key);
    if (!matched) {
      return res.status(400).json({ message: 'Incorrect encryption key' });
    }

    // Encrypt the username and password
    const encryptedUsername = encrypt(username, encryption_key);
    const encryptedPassword = encrypt(password, encryption_key);

    // Save the password record
    await UserPassword.create({
      ownerUserId: userId,
      url,
      username: encryptedUsername,
      password: encryptedPassword,
      label,
    });

    res.status(200).json({ message: 'Password is saved' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// List passwords
app.post('/passwords/list', authenticateToken, async (req, res) => {
  try {
    const { encryption_key } = req.body;
    const userId = req.auth.userId;

    // Find the user and verify the encryption key
    const userRecord = await AppUser.findOne({
      attributes: ['encryption_key'],
      where: { id: userId },
    });
    if (!userRecord) {
      return res.status(403).json({ message: 'Unable to find the account' });
    }
    const matched = await bcrypt.compare(encryption_key, userRecord.encryption_key);
    if (!matched) {
      return res.status(400).json({ message: 'Incorrect encryption key' });
    }

    // Fetch all passwords owned by the user
    const passwords = await UserPassword.findAll({
      attributes: ['id', 'url', 'username', 'password', 'label', 'weak_encryption'],
      where: { ownerUserId: userId },
    });

    const passwordsArr = [];
    for (const element of passwords) {
      if (element.weak_encryption) {
        // Decrypt with the user's encryption key hash and re-encrypt with the actual encryption key
        const decryptedPassword = decrypt(element.password, userRecord.encryption_key);
        const decryptedUsername = decrypt(element.username, userRecord.encryption_key);
        element.password = encrypt(decryptedPassword, encryption_key);
        element.username = encrypt(decryptedUsername, encryption_key);
        element.weak_encryption = false;
        await element.save();
      }

      // Decrypt the username and password
      element.password = decrypt(element.password, encryption_key);
      element.username = decrypt(element.username, encryption_key);
      passwordsArr.push(element);
    }

    res.status(200).json({ message: 'Success', data: passwordsArr });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Share a password
app.post('/passwords/share-password', authenticateToken, async (req, res) => {
  try {
    const { password_id, encryption_key, email } = req.body;
    const userId = req.auth.userId;

    // Find the password record
    const passwordRow = await UserPassword.findOne({
      attributes: ['label', 'url', 'username', 'password'],
      where: { id: password_id, ownerUserId: userId },
    });
    if (!passwordRow) {
      return res.status(400).json({ message: 'Incorrect password_id' });
    }

    // Verify the encryption key
    const userRecord = await AppUser.findOne({
      attributes: ['encryption_key'],
      where: { id: userId },
    });
    const matched = await bcrypt.compare(encryption_key, userRecord.encryption_key);
    if (!matched) {
      return res.status(400).json({ message: 'Incorrect encryption key' });
    }

    // Find the user to share the password with
    const shareUserObj = await AppUser.findOne({
      attributes: ['id', 'encryption_key'],
      where: { email },
    });
    if (!shareUserObj) {
      return res.status(400).json({ message: 'User with whom you want to share password does not exist' });
    }

    // Check if the password is already shared
    const existingSharedPassword = await UserPassword.findOne({
      attributes: ['id'],
      where: { source_password_id: password_id, ownerUserId: shareUserObj.id },
    });
    if (existingSharedPassword) {
      return res.status(400).json({ message: 'This password is already shared with the user' });
    }

    // Decrypt and re-encrypt the username and password for the shared user
    const decryptedUserName = decrypt(passwordRow.username, encryption_key);
    const encryptedSharedUserName = encrypt(decryptedUserName, shareUserObj.encryption_key);
    const decryptedPassword = decrypt(passwordRow.password, encryption_key);
    const encryptedSharedPassword = encrypt(decryptedPassword, shareUserObj.encryption_key);

    // Create the shared password record
    await UserPassword.create({
      ownerUserId: shareUserObj.id,
      label: passwordRow.label,
      url: passwordRow.url,
      username: encryptedSharedUserName,
      password: encryptedSharedPassword,
      sharedByUserId: userId,
      weak_encryption: true,
      source_password_id: password_id,
    });

    res.status(200).json({ message: 'Password shared successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
