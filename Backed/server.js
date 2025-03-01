const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(bodyParser.json());

mongoose.connect('mongodb://localhost:27017/auction', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

const AuctionSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: String,
    startingBid: { type: Number, required: true },
    currentBid: Number,
    highestBidder: String,
    endTime: { type: Date, required: true },
    isClosed: { type: Boolean, default: false },
});

const User = mongoose.model('User', UserSchema);
const Auction = mongoose.model('Auction', AuctionSchema);

const authenticate = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access denied' });
    try {
        const verified = jwt.verify(token.replace('Bearer ', ''), 'your_jwt_secret');
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid token' });
    }
};

app.post('/signup', async (req, res) => {
    try {
        const newUser = new User(req.body);
        await newUser.save();
        res.json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/signin', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
        return res.status(400).json({ error: 'User not found' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, 'your_jwt_secret', { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
});

app.post('/auction', authenticate, async (req, res) => {
    try {
        const newAuction = new Auction(req.body);
        await newAuction.save();
        res.json({ message: 'Auction created successfully' });
    } catch (error) {
        res.status(400).json({ error: 'Error creating auction' });
    }
});

app.post('/bid/:id', authenticate, async (req, res) => {
    const { bidAmount } = req.body;
    const auction = await Auction.findById(req.params.id);
    const userId = req.user.userId;

    if (!auction) {
        return res.status(400).json({ error: 'Auction not found' });
    }

    if (new Date() > auction.endTime) {
        auction.isClosed = true;
        await auction.save();
        return res.status(400).json({ error: 'Auction is closed' });
    }

    if (!auction.currentBid || bidAmount > auction.currentBid) {
        auction.currentBid = bidAmount;
        auction.highestBidder = userId;
        await auction.save();
        return res.json({ message: 'Bid placed successfully' });
    } else {
        return res.status(400).json({ error: 'Bid must be higher than current bid' });
    }
});

app.get('/auctions', async (req, res) => {
    const auctions = await Auction.find();
    res.json(auctions);
});

app.get('/auctions/:id', async (req, res) => {
    const auction = await Auction.findById(req.params.id);
    if (!auction) {
        return res.status(400).json({ error: 'Auction not found' });
    }
    res.json(auction);
});

app.listen(5000, () => {
    console.log('Server running on port 5000');
});



