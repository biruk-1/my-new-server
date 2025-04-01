const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccountKey.json');
const bcrypt = require('bcrypt');

// Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const app = express();
app.use(cors({
  origin: '*', // Allow all origins for testing
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Initialize Firestore
const db = admin.firestore();

// Generate OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Hash password
const hashPassword = async (password) => {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
};

// Register new user
app.post('/api/register', async (req, res) => {
  try {
    const { phoneNumber, fullName, birthDate, password, userAge } = req.body;

    console.log('Registration request received:', { phoneNumber, fullName, birthDate });

    // Check if user already exists
    const userRef = db.collection('users').doc(phoneNumber);
    const userDoc = await userRef.get();

    if (userDoc.exists) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Generate OTP
    const otp = generateOTP();
    
    // Store user data and OTP in Firestore
    await userRef.set({
      fullName,
      phoneNumber,
      birthDate,
      userAge: userAge || null,
      password: hashedPassword,
      otp,
      otpExpiry: admin.firestore.Timestamp.fromDate(new Date(Date.now() + 60 * 1000)), // 1 minute expiry
      verified: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // In a production environment, you would send the OTP via SMS here
    console.log(`OTP for ${phoneNumber}: ${otp}`);

    res.status(200).json({ message: 'Registration successful. OTP sent.' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed: ' + error.message });
  }
});

// Resend OTP
app.post('/api/resend-otp', async (req, res) => {
  try {
    const { phoneNumber } = req.body;

    console.log('Resend OTP request for:', phoneNumber);

    const userRef = db.collection('users').doc(phoneNumber);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate new OTP
    const otp = generateOTP();

    // Update OTP and expiry
    await userRef.update({
      otp,
      otpExpiry: admin.firestore.Timestamp.fromDate(new Date(Date.now() + 60 * 1000)), // 1 minute expiry
    });

    // In a production environment, you would send the OTP via SMS here
    console.log(`New OTP for ${phoneNumber}: ${otp}`);

    res.status(200).json({ message: 'New OTP sent successfully' });
  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ error: 'Failed to resend OTP: ' + error.message });
  }
});

// Change phone number
app.post('/api/change-phone', async (req, res) => {
  try {
    const { oldPhoneNumber, newPhoneNumber } = req.body;

    console.log('Change phone request:', { oldPhoneNumber, newPhoneNumber });

    // Check if new phone number is already registered
    const newUserRef = db.collection('users').doc(newPhoneNumber);
    const newUserDoc = await newUserRef.get();

    if (newUserDoc.exists) {
      return res.status(409).json({ error: 'Phone number already registered' });
    }

    // Get old user data
    const oldUserRef = db.collection('users').doc(oldPhoneNumber);
    const oldUserDoc = await oldUserRef.get();

    if (!oldUserDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = oldUserDoc.data();
    const otp = generateOTP();

    // Create new user document
    await newUserRef.set({
      ...userData,
      phoneNumber: newPhoneNumber,
      otp,
      otpExpiry: admin.firestore.Timestamp.fromDate(new Date(Date.now() + 60 * 1000)), // 1 minute expiry
      verified: false,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Delete old user document
    await oldUserRef.delete();

    // In a production environment, you would send the OTP via SMS here
    console.log(`New OTP for ${newPhoneNumber}: ${otp}`);

    res.status(200).json({ message: 'Phone number updated. New OTP sent.' });
  } catch (error) {
    console.error('Change phone error:', error);
    res.status(500).json({ error: 'Failed to change phone number: ' + error.message });
  }
});

// Verify OTP
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { phoneNumber, otp } = req.body;

    console.log('Verify OTP request:', { phoneNumber, otp });

    const userRef = db.collection('users').doc(phoneNumber);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = userDoc.data();
    const now = admin.firestore.Timestamp.now();

    if (userData.otp !== otp) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    if (now > userData.otpExpiry) {
      return res.status(400).json({ error: 'OTP expired' });
    }

    // Mark user as verified
    await userRef.update({
      verified: true,
      otp: null,
      otpExpiry: null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Create a custom token for the user
    const customToken = await admin.auth().createCustomToken(phoneNumber);

    res.status(200).json({ token: customToken });
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'Verification failed: ' + error.message });
  }
});

// Login user
app.post('/api/login', async (req, res) => {
  try {
    const { phoneNumber, password } = req.body;

    console.log('Login request for:', phoneNumber);

    const userRef = db.collection('users').doc(phoneNumber);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'Account not found' });
    }

    const userData = userDoc.data();

    // Compare hashed password
    const isPasswordMatch = await bcrypt.compare(password, userData.password);

    if (!isPasswordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!userData.verified) {
      // If not verified, generate new OTP and send
      const otp = generateOTP();
      
      await userRef.update({
        otp,
        otpExpiry: admin.firestore.Timestamp.fromDate(new Date(Date.now() + 60 * 1000))
      });
      
      console.log(`New OTP for verification: ${otp}`);
      
      return res.status(403).json({ 
        error: 'Please verify your phone number first',
        needsVerification: true,
        phoneNumber
      });
    }

    // Create a custom token for the user
    const customToken = await admin.auth().createCustomToken(phoneNumber);
    
    // Update last login
    await userRef.update({
      lastLogin: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(200).json({ token: customToken, user: {
      fullName: userData.fullName,
      phoneNumber: userData.phoneNumber,
      verified: userData.verified
    }});
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed: ' + error.message });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'OK', message: 'Server is running' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
}); 