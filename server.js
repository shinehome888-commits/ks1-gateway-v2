require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// --- 1. DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ DB Error:', err));

// --- 2. MODELS ---
const UserSchema = new mongoose.Schema({
  phone_number: { type: String, unique: true, required: true },
  email: { type: String, sparse: true },
  password_hash: { type: String, required: true },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  reset_code: { type: String, default: null },
  reset_expires: { type: Date, default: null }
});
const User = mongoose.model('User', UserSchema);

const WalletSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  usdc_balance: { type: Number, default: 0 },
  eth_balance: { type: Number, default: 0 }
});
const Wallet = mongoose.model('Wallet', WalletSchema);

const TransactionSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  amount: Number,
  fee: Number,
  asset: String,
  date: { type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', TransactionSchema);

const TreasurySchema = new mongoose.Schema({
  amount: Number,
  asset: String,
  date: { type: Date, default: Date.now }
});
const Treasury = mongoose.model('Treasury', TreasurySchema);

// --- 3. SETUP DEMO USERS ---
async function setupUsers() {
  try {
    const count = await User.countDocuments();
    if (count === 0) {
      console.log('🔄 Creating demo users...');
      const h1 = await bcrypt.hash('demo123', 10);
      const h2 = await bcrypt.hash('admin123', 10);
      
      const u1 = await User.create({ phone_number: '233555123456', email: 'user@ks1.com', password_hash: h1, role: 'user' });
      await Wallet.create({ user: u1._id, usdc_balance: 1000, eth_balance: 5 });
      
      const u2 = await User.create({ phone_number: '233555987654', email: 'admin@ks1.com', password_hash: h2, role: 'admin' });
      await Wallet.create({ user: u2._id, usdc_balance: 0, eth_balance: 0 });
      
      console.log('🎁 Demo Users Created Successfully!');
    } else {
      console.log('ℹ️ Users already exist.');
    }
  } catch (e) {
    console.error('Setup error:', e);
  }
}

// --- 4. MIDDLEWARE ---
const auth = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'ks1_secret');
    next();
  } catch (e) {
    res.status(400).json({ success: false, message: 'Invalid token' });
  }
};

// --- 5. ROUTES ---

// Home
app.get('/', (req, res) => res.json({ status: '🟢 KS1 Gateway V2 Online' }));

// Login
app.post('/api/v1/auth/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) return res.status(400).json({ success: false, message: 'Missing credentials' });

  try {
    const user = await User.findOne({ $or: [{ phone_number: identifier }, { email: identifier }] });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ success: false, message: 'Wrong password' });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET || 'ks1_secret', { expiresIn: '24h' });

    // ✅ FIXED: 'data' key explicitly written
    res.json({
      success: true,
      message: 'Login successful',
       {
        token: token,
        user: { phone: user.phone_number, role: user.role }
      }
    });
  } catch (e) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Admin Generate Reset Code
app.post('/api/v1/admin/generate-reset-code', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Access denied' });
  
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ success: false, message: 'User ID required' });

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const codeNum = Math.floor(1000 + Math.random() * 9000);
    const resetCode = `KS1-${codeNum}`;
    
    user.reset_code = resetCode;
    user.reset_expires = new Date(Date.now() + 60 * 60 * 1000); 
    await user.save();

    // ✅ FIXED: 'data' key explicitly written
    res.json({
      success: true,
      message: `Reset code generated for ${user.phone_number}`,
       { resetCode, phone: user.phone_number }
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// User Reset Password
app.post('/api/v1/auth/reset-password', async (req, res) => {
  const { identifier, code, newPassword } = req.body;
  if (!identifier || !code || !newPassword) return res.status(400).json({ success: false, message: 'Missing fields' });

  try {
    const user = await User.findOne({ $or: [{ phone_number: identifier }, { email: identifier }] });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    if (!user.reset_code || user.reset_code !== code) {
      return res.status(400).json({ success: false, message: 'Invalid reset code' });
    }

    if (user.reset_expires && new Date() > user.reset_expires) {
      return res.status(400).json({ success: false, message: 'Reset code expired' });
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    user.password_hash = newHash;
    user.reset_code = null;
    user.reset_expires = null;
    await user.save();

    res.json({ success: true, message: 'Password updated successfully! Please login.' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Search User by Phone
app.get('/api/v1/users/search', auth, async (req, res) => {
  const { phone } = req.query;
  if (!phone) return res.status(400).json({ success: false, message: 'Phone required' });
  try {
    const clean = phone.replace(/[\+\- ]/g, '');
    const user = await User.findOne({ phone_number: new RegExp('^' + clean, 'i') });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    
    // ✅ FIXED: 'data' key explicitly written
    res.json({
      success: true,
       { userId: user._id, phone: user.phone_number }
    });
  } catch (e) {
    res.status(500).json({ success: false, message: 'Error' });
  }
});

// Transfer
app.post('/api/v1/p2p/transfer', auth, async (req, res) => {
  const { receiverId, asset, amount } = req.body;
  if (!receiverId || !asset || !amount) return res.status(400).json({ success: false, message: 'Missing fields' });
  
  try {
    const senderWallet = await Wallet.findOne({ user: req.user.id });
    const key = asset.toLowerCase() + '_balance';
    if (!senderWallet || senderWallet[key] < amount) return res.status(400).json({ success: false, message: 'Insufficient funds' });

    const fee = parseFloat((amount * 0.01).toFixed(8));
    const net = amount - fee;

    senderWallet[key] -= amount;
    await senderWallet.save();

    let recvWallet = await Wallet.findOne({ user: receiverId });
    if (!recvWallet) recvWallet = await Wallet.create({ user: receiverId, [key]: 0 });
    
    recvWallet[key] += net;
    await recvWallet.save();

    await Transaction.create({ sender: req.user.id, receiver: receiverId, amount, fee, asset });
    await Treasury.create({ amount: fee, asset });

    // ✅ FIXED: 'data' key explicitly written
    res.json({
      success: true,
      message: 'Transfer successful',
       { treasury_fee: fee, new_balance: senderWallet[key] }
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Admin Treasury
app.get('/api/v1/admin/treasury', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Access denied' });
  const stats = await Treasury.aggregate([{ $group: { _id: '$asset', total: { $sum: '$amount' } } }]);
  
  // ✅ FIXED: 'data' key explicitly written
  res.json({ 
    success: true, 
     stats 
  });
});

// Admin Get All Users (Fixes the 404 Error)
app.get('/api/v1/admin/users', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Access denied' });
  try {
    const users = await User.find({}, 'phone_number email role createdAt');
    // ✅ FIXED: 'data' key explicitly written
    res.json({ 
      success: true, 
       users 
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// --- 6. START ---
app.listen(PORT, async () => {
  await setupUsers();
  console.log(`🚀 Server running on port ${PORT}`);
});
