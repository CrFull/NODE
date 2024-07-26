const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 5000;
const secret = 'your_jwt_secret'; // Replace with your own secret

app.use(cors());
app.use(bodyParser.json());

mongoose.connect('mongodb://localhost:27017/bodyweight')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const WeightSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true },
  date: { type: Date, required: true },
  weight: { type: Number, required: true }
});

const User = mongoose.model('User', UserSchema);
const Weight = mongoose.model('Weight', WeightSchema);

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (user) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();

  const token = jwt.sign({ userId: newUser._id }, secret, { expiresIn: '1h' });
  res.json({ token });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (user) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();

  const token = jwt.sign({ userId: newUser._id, username: newUser.username }, secret, { expiresIn: '1h' });
  res.json({ token, username: newUser.username });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user._id, username: user.username }, secret, { expiresIn: '1h' });
  res.json({ token, username: user.username });
});



const authMiddleware = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, secret);
    req.userId = decoded.userId;
    next();
  } catch (e) {
    res.status(400).json({ message: 'Token is not valid' });
  }
};

app.get('/weights', authMiddleware, async (req, res) => {
  const weights = await Weight.find({ userId: req.userId });
  res.json(weights);
});

app.post('/weights', authMiddleware, async (req, res) => {
  const newWeight = new Weight({ userId: req.userId, ...req.body });
  await newWeight.save();
  res.json(newWeight);
});

app.delete('/weights/:id', authMiddleware, async (req, res) => {
  await Weight.findOneAndDelete({ _id: req.params.id, userId: req.userId });
  res.json({ message: 'Weight log deleted' });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
