const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();



app.use(cors({
  origin: ['https://tutorgram-backend.onrender.com','http://localhost:3000', 'http://127.0.0.1:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));


app.use(express.json());

// --- MONGODB CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected Successfully"))
  .catch(err => console.error("MongoDB Connection Error:", err));

// --- USER MODEL ---
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'Student' },
  avatarUrl: String,
  xp: { type: Number, default: 0 },
  streak: { type: Number, default: 0 },
  lastActiveDate: String,
  totalLearningDays: { type: Number, default: 0 },
  completedTopics: [String],
  quizScores: { type: Map, of: Number },
  joinedDate: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// --- ROUTES ---

// 1. SIGNUP
app.post('/api/auth/signup', async (req, res) => {
  console.log("Signup Request Received:", req.body.email);
  try {
    const { name, email, password, avatarUrl } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User already exists" });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name, email,
      password: hashedPassword,
      avatarUrl,
      lastActiveDate: new Date().toISOString().split('T')[0]
    });

    await newUser.save();

    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET || 'secret');

    console.log("User Created:", newUser.email);
    res.json({ token, user: newUser });
  } catch (err) {
    console.error("Signup Error:", err);
    res.status(500).json({ error: err.message });
  }
});

// 2. LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'secret');
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. UPDATE PROGRESS
app.put('/api/user/update', async (req, res) => {
  try {
    const { userId, updates } = req.body;
    const user = await User.findByIdAndUpdate(userId, updates, { new: true });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. LEADERBOARD
app.get('/api/leaderboard', async (req, res) => {
  try {
    const users = await User.find().sort({ xp: -1 }).limit(5);
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET ME (Verify Token & Get User)
app.get('/api/auth/me', async (req, res) => {
  try {
    // 1. Get token from header
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "No token provided" });

    // 2. Verify Token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');

    // 3. Find User
    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json(user);
  } catch (err) {
    res.status(401).json({ message: "Invalid Token" });
  }
});

app.get('/', async (req, res) => {
  res.status(201).json({message:"backend is running"})
})

const PORT = 8080;
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));