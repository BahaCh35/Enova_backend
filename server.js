const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();

// JWT Secret
const JWT_SECRET = 'H4PrJqonnJ5YnZbvafHHWuoDvtn2vRSq';

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Role-based middleware
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Ensure 'uploads/' folder exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/internshipDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(async () => {
  console.log('✅ MongoDB connected');
  await createDefaultAdmin(); // ← Create admin user after DB connects
  const metricsExists = await Metrics.findOne();
  if (!metricsExists) {
    await Metrics.create({ employees: 0, present: 0, absent: 0 });
    console.log('✅ Default metrics created');
  }
})
.catch(err => console.error('❌ MongoDB error:', err));

// ----- MODELS -----
const productSchema = new mongoose.Schema({
  name: String,
  description: String,
  image: String
});
const Product = mongoose.model('Product', productSchema);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  role: { type: String, default: 'user' }
});
const User = mongoose.model('User', userSchema);

// ----- METRICS MODEL -----
const metricsSchema = new mongoose.Schema({
  employees: { type: Number, default: 0 },
  present: { type: Number, default: 0 },
  absent: { type: Number, default: 0 }
}, { timestamps: true });
const Metrics = mongoose.model('Metrics', metricsSchema);

// ----- MULTER -----
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// ----- CREATE DEFAULT ADMIN -----
async function createDefaultAdmin() {
  const exists = await User.findOne({ email: 'admin@gmail.com' });
  if (!exists) {
    const hashedPassword = await bcrypt.hash('321', 10);
    const newUser = new User({
      email: 'admin@gmail.com',
      password: hashedPassword,
      role: 'admin'
    });
    await newUser.save();
    console.log('✅ Default admin user created');
  } else {
    console.log('ℹ️ Admin already exists');
  }
}

// ROUTES 

// Register route
app.post('/register', async (req, res) => {
  const { email, password, role } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      email,
      password: hashedPassword,
      role: role || 'user'
    });
    await newUser.save();

    res.json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ 
      message: 'Login successful', 
      token,
      user: { email: user.email, role: user.role, id: user._id }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// ----- METRICS ROUTES -----
// Read metrics (any authenticated user)
app.get('/metrics', authenticateToken, async (req, res) => {
  try {
    const metrics = await Metrics.findOne();
    res.json(metrics || { employees: 0, present: 0, absent: 0 });
  } catch (err) {
    console.error('GET metrics error:', err);
    res.status(500).json({ error: 'Error fetching metrics' });
  }
});

// Update metrics (admin only)
app.put('/metrics', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const employees = Math.max(0, Number(req.body.employees || 0));
    const present = Math.max(0, Number(req.body.present || 0));
    const absent = Math.max(0, Number(req.body.absent || 0));

    const updated = await Metrics.findOneAndUpdate(
      {},
      { employees, present, absent },
      { new: true, upsert: true }
    );
    res.json({ message: 'Metrics updated', metrics: updated });
  } catch (err) {
    console.error('PUT metrics error:', err);
    res.status(500).json({ error: 'Failed to update metrics' });
  }
});
// Get all products (protected)
app.get('/products', authenticateToken, async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    console.error('GET error:', err);
    res.status(500).json({ error: 'Error fetching products' });
  }
});

// Add product (protected - admin and user can add)
app.post('/api/products', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { name, description } = req.body;
    const image = req.file ? req.file.path : '';

    const newProduct = new Product({ name, description, image });
    await newProduct.save();

    res.json({ message: 'Product added', product: newProduct });
  } catch (err) {
    console.error('POST error:', err);
    res.status(500).json({ error: 'Failed to add product' });
  }
});

// Delete product (protected - admin and user can delete)
app.delete('/products/:id', authenticateToken, async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product deleted' });
  } catch (err) {
    console.error('DELETE error:', err);
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

// Update product (protected - admin and user can update)
app.put('/products/:id', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { name, description } = req.body;
    const updateFields = { name, description };

    if (req.file) {
      updateFields.image = req.file.path;
    }

    const updatedProduct = await Product.findByIdAndUpdate(
      req.params.id,
      updateFields,
      { new: true }
    );

    res.json({ message: 'Product updated', product: updatedProduct });
  } catch (err) {
    console.error('PUT error:', err);
    res.status(500).json({ error: 'Failed to update product' });
  }
});

// User management routes (admin only)
app.get('/users', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 }); // Exclude passwords
    res.json(users);
  } catch (err) {
    console.error('GET users error:', err);
    res.status(500).json({ error: 'Error fetching users' });
  }
});

app.delete('/users/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'User deleted' });
  } catch (err) {
    console.error('DELETE user error:', err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Get current user profile
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId, { password: 0 });
    res.json(user);
  } catch (err) {
    console.error('GET profile error:', err);
    res.status(500).json({ error: 'Error fetching profile' });
  }
});



// Start server
app.listen(5000, () => {
  console.log('🚀 Backend running on http://localhost:5000');
});



