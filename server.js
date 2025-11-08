import dotenv from 'dotenv';
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import axios from 'axios';

// For __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('../')); // Serve frontend files

// MongoDB Connection
const MONGODB_URI = 'mongodb+srv://chandan:6QJ8O1GihYgEotag@store.plmwltk.mongodb.net/anvik-biotecch?retryWrites=true&w=majority';

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB Atlas'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// MongoDB Schemas
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'customer'], default: 'customer' },
    name: String,
    email: String,
    phone: String,
    address: {
        street: String,
        city: String,
        state: String,
        pincode: String
    }
}, { timestamps: true });

const medicineSchema = new mongoose.Schema({
    image: { type: String, default: "https://via.placeholder.com/40" },
    name: { type: String, required: true },
    batchNo: { type: String, required: true },
    category: { type: String, required: true },
    price: { type: Number, required: true },
    totalQty: { type: Number, required: true },
    soldQty: { type: Number, required: true, default: 0 },
    expiryDate: { type: Date, required: true }
}, { timestamps: true });

// UPDATED ORDER SCHEMA - customer is now optional
const orderSchema = new mongoose.Schema({
    orderId: { type: String, required: true, unique: true },
    customer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false }, // CHANGED TO false
    items: [{
        medicine: { type: mongoose.Schema.Types.ObjectId, ref: 'Medicine' },
        name: String,
        price: Number,
        quantity: Number
    }],
    totalAmount: { type: Number, required: true },
    shippingAddress: {
        name: String,
        email: String,
        phone: String,
        address: String,
        city: String,
        state: String,
        pincode: String
    },
    paymentMethod: { type: String, enum: ['cashfree', 'cod', 'devcraftor'], required: true },
    paymentStatus: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
    orderStatus: { type: String, enum: ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'], default: 'pending' },
    cashfreeOrderId: String,
    cashfreePaymentId: String
}, { timestamps: true });

// Models
const User = mongoose.model('User', userSchema);
const Medicine = mongoose.model('Medicine', medicineSchema);
const Order = mongoose.model('Order', orderSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'anvik-biotecch-secret-key';

// Cashfree credentials and configuration
const CASHFREE_APP_ID = '10894880eacc84717e1b5f6f24f8849801';
const CASHFREE_SECRET = 'cfsk_ma_prod_28fa1a3da8ba0cde10ed4d64bb48f6ff_5ed3518d';
const CASHFREE_ENV = 'PRODUCTION';
const CASHFREE_API_VERSION = '2022-09-01';
const CASHFREE_BASE = 'https://api.cashfree.com/pg';
const CASHFREE_ORDERS_URL = `${CASHFREE_BASE}/orders`;

// Function to test Cashfree API connectivity
const testCashfreeAPI = async () => {
    try {
        const response = await fetch(CASHFREE_ORDERS_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-client-id': CASHFREE_APP_ID,
                'x-client-secret': CASHFREE_SECRET,
                'x-api-version': CASHFREE_API_VERSION
            },
            body: JSON.stringify({
                order_id: 'TEST' + Date.now(),
                order_amount: 1.00,
                order_currency: 'INR',
                customer_details: {
                    customer_id: 'TEST_CUSTOMER',
                    customer_email: 'test@example.com',
                    customer_phone: '9999999999'
                }
            })
        });
        
        const data = await response.text();
        console.log('Cashfree API Test Response:', {
            status: response.status,
            statusText: response.statusText,
            headers: Object.fromEntries(response.headers),
            body: data
        });
        return response.ok;
    } catch (error) {
        console.error('Cashfree API Test Failed:', error);
        return false;
    }
};

// Log Cashfree configuration on startup (without sensitive data)
console.log('Initializing Cashfree with config:', {
    environment: CASHFREE_ENV,
    apiVersion: CASHFREE_API_VERSION,
    baseUrl: CASHFREE_BASE,
    appId: CASHFREE_APP_ID.substring(0, 8) + '...'
}); // Always use production endpoint

// Use global fetch when available, otherwise dynamically import node-fetch
const fetchFn = global.fetch || ((...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args)));

// Auth Middleware
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '') || '';

        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        // verify token and attach both payload and user (when available)
        const decoded = jwt.verify(token, JWT_SECRET);
        req.tokenPayload = decoded;

        // try to fetch full user from DB; if not found, keep payload as fallback
        const user = await User.findById(decoded.userId).select('-password');
        if (user) {
            req.user = user;
        } else {
            // fallback user-like object from token payload
            req.user = { _id: decoded.userId, role: decoded.role };
        }

        next();
    } catch (error) {
        res.status(401).json({ error: 'Token verification failed' });
    }
};

// Admin Middleware
const adminMiddleware = (req, res, next) => {
    const role = (req.user && req.user.role) || (req.tokenPayload && req.tokenPayload.role);
    if (!role) {
        return res.status(401).json({ error: 'No role information available' });
    }

    if (role !== 'admin') {
        return res.status(403).json({ error: 'Access denied. Admin only.' });
    }
    next();
};

// Routes

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, name, email, phone, role } = req.body;

        // Check if user exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = new User({
            username,
            password: hashedPassword,
            name,
            email,
            phone,
            role: role || 'customer'
        });

        await user.save();

        // Generate token
        const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET);

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: user._id,
                username: user.username,
                name: user.name,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Generate token
        const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET);

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                username: user.username,
                name: user.name,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Medicine Routes
app.get('/api/medicines', async (req, res) => {
    try {
        // For customers, only show medicines with available quantity > 0
        const token = req.header('Authorization')?.replace('Bearer ', '');
        let isAdmin = false;
        
        // Check if user is admin
        if (token) {
            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                const user = await User.findById(decoded.userId);
                if (user && user.role === 'admin') {
                    isAdmin = true;
                }
            } catch (err) {
                console.log('Invalid token, showing available medicines only');
            }
        }
        
        // Fetch all medicines
        const medicines = await Medicine.find({});
        
        // Calculate availableQty and stockStatus for each medicine
        let result = medicines.map(med => {
            const availableQty = (med.totalQty || 0) - (med.soldQty || 0);
            let stockStatus = "Out of Stock";
            if (availableQty > 10) stockStatus = "In Stock";
            else if (availableQty > 0) stockStatus = "Low Stock";
            return {
                ...med.toObject(),
                availableQty,
                stockStatus
            };
        });
        
        // For customers (non-admin), filter out medicines with no available quantity
        if (!isAdmin) {
            result = result.filter(med => med.availableQty > 0);
        }
        
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Sample data seeding endpoint (run once to add sample medicines)
app.post('/api/medicines/seed', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        // Check if medicines already exist
        const existingCount = await Medicine.countDocuments();
        if (existingCount > 0) {
            return res.status(400).json({ 
                error: 'Medicines already exist. Delete existing medicines first or use the add medicine form.' 
            });
        }

        const sampleMedicines = [
            {
                image: "https://via.placeholder.com/40",
                name: "Paracetamol 500mg",
                batchNo: "BATCH001",
                category: "tablet",
                price: 15.50,
                totalQty: 500,
                soldQty: 0,
                expiryDate: new Date("2026-12-31")
            },
            {
                image: "https://via.placeholder.com/40",
                name: "Cough Syrup - Brohex",
                batchNo: "BATCH002",
                category: "syrup",
                price: 85.00,
                totalQty: 200,
                soldQty: 0,
                expiryDate: new Date("2027-06-30")
            },
            {
                image: "https://via.placeholder.com/40",
                name: "Amoxicillin 250mg",
                batchNo: "BATCH003",
                category: "injection",
                price: 45.00,
                totalQty: 150,
                soldQty: 0,
                expiryDate: new Date("2026-09-15")
            },
            {
                image: "https://via.placeholder.com/40",
                name: "Antibacterial Ointment",
                batchNo: "BATCH004",
                category: "ointment",
                price: 120.00,
                totalQty: 100,
                soldQty: 0,
                expiryDate: new Date("2027-03-20")
            }
        ];

        await Medicine.insertMany(sampleMedicines);
        
        res.status(201).json({ 
            success: true,
            message: `Successfully added ${sampleMedicines.length} sample medicines`,
            count: sampleMedicines.length
        });
    } catch (error) {
        console.error('Error seeding medicines:', error);
        res.status(500).json({ error: error.message || 'Failed to seed medicines' });
    }
});

// Update medicine stock
app.post('/api/medicines/:id/updateStock', authMiddleware, async (req, res) => {
    try {
        const { addQuantity } = req.body;
        
        if (typeof addQuantity !== 'number' || addQuantity <= 0) {
            return res.status(400).json({ error: 'Invalid quantity' });
        }

        const medicine = await Medicine.findById(req.params.id);
        if (!medicine) {
            return res.status(404).json({ error: 'Medicine not found' });
        }

        // Update stock - add to totalQty
        medicine.totalQty = (medicine.totalQty || 0) + addQuantity;
        await medicine.save();

        const availableQty = (medicine.totalQty || 0) - (medicine.soldQty || 0);

        res.json({ 
            message: 'Stock updated successfully',
            newQuantity: availableQty,
            totalQty: medicine.totalQty
        });
    } catch (error) {
        console.error('Error updating stock:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/medicines/:id', async (req, res) => {
    try {
        const medicine = await Medicine.findById(req.params.id);
        if (!medicine) {
            return res.status(404).json({ error: 'Medicine not found' });
        }
        res.json(medicine);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/medicines', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        // Validate required fields
        const { name, batchNo, category, price, totalQty, expiryDate, soldQty, image } = req.body;
        
        if (!name || !name.trim()) {
            return res.status(400).json({ error: 'Medicine name is required' });
        }
        if (!batchNo || !batchNo.trim()) {
            return res.status(400).json({ error: 'Batch number is required' });
        }
        if (!category || !category.trim()) {
            return res.status(400).json({ error: 'Category is required' });
        }
        if (typeof price !== 'number' || price <= 0) {
            return res.status(400).json({ error: 'Valid price is required' });
        }
        if (typeof totalQty !== 'number' || totalQty < 0) {
            return res.status(400).json({ error: 'Valid quantity is required' });
        }
        if (!expiryDate) {
            return res.status(400).json({ error: 'Expiry date is required' });
        }

        // Create medicine object
        const medicineData = {
            name: name.trim(),
            batchNo: batchNo.trim(),
            category: category.trim(),
            price: price,
            totalQty: totalQty,
            soldQty: soldQty || 0,
            expiryDate: new Date(expiryDate),
            image: image || "https://via.placeholder.com/40"
        };

        console.log('Creating medicine with data:', medicineData);

        const medicine = new Medicine(medicineData);
        await medicine.save();
        
        res.status(201).json({ 
            message: 'Medicine added successfully', 
            medicine: medicine.toObject()
        });
    } catch (error) {
        console.error('Error adding medicine:', error);
        // Handle validation errors
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(e => e.message).join(', ');
            return res.status(400).json({ error: 'Validation error: ' + errors });
        }
        // Handle duplicate key errors
        if (error.code === 11000) {
            return res.status(400).json({ error: 'Medicine with this batch number already exists' });
        }
        res.status(500).json({ error: error.message || 'Failed to add medicine' });
    }
});

app.put('/api/medicines/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const medicine = await Medicine.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true }
        );
        if (!medicine) {
            return res.status(404).json({ error: 'Medicine not found' });
        }
        res.json({ message: 'Medicine updated successfully', medicine });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/medicines/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const medicine = await Medicine.findByIdAndDelete(req.params.id);
        if (!medicine) {
            return res.status(404).json({ error: 'Medicine not found' });
        }
        res.json({ message: 'Medicine permanently deleted from database' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Order Routes

// Guest Order Route (No login required)
app.post('/api/orders/guest', async (req, res) => {
    try {
        const { items, shippingAddress, paymentMethod, totalAmount } = req.body;
        
        // Validate required fields
        if (!items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ error: 'Order must contain items' });
        }

        if (!shippingAddress) {
            return res.status(400).json({ error: 'Shipping address is required' });
        }

        if (!totalAmount || totalAmount <= 0) {
            return res.status(400).json({ error: 'Invalid total amount' });
        }

        // Validate stock availability before creating order
        const stockValidationErrors = [];
        for (const item of items) {
            const medicine = await Medicine.findById(item.medicine);
            if (!medicine) {
                stockValidationErrors.push(`${item.name || 'Unknown item'}: Medicine not found`);
                continue;
            }
            
            const availableQty = (medicine.totalQty || 0) - (medicine.soldQty || 0);
            if (availableQty < item.quantity) {
                stockValidationErrors.push(`${item.name || medicine.name}: Only ${availableQty} units available, requested ${item.quantity}`);
            }
        }
        
        if (stockValidationErrors.length > 0) {
            return res.status(400).json({ 
                error: 'Insufficient stock for some items',
                details: stockValidationErrors
            });
        }
        
        // Generate order ID
        const orderId = 'ORD' + Date.now();
        
        const order = new Order({
            orderId,
            items,
            shippingAddress,
            paymentMethod,
            totalAmount,
            orderStatus: 'pending',
            customer: null // Guest orders have no customer
        });

        await order.save();

        // Update medicine stock by incrementing soldQty
        for (const item of items) {
            await Medicine.findByIdAndUpdate(
                item.medicine,
                { $inc: { soldQty: item.quantity } }
            );
        }
        
        res.status(201).json({ 
            message: 'Order created successfully', 
            order: {
                orderId: order.orderId,
                items: order.items,
                totalAmount: order.totalAmount,
                shippingAddress: order.shippingAddress,
                orderStatus: order.orderStatus
            }
        });
    } catch (error) {
        console.error('Error creating guest order:', error);
        res.status(500).json({ error: error.message });
    }
});

// Customer orders (for logged-in customers)
app.post('/api/orders', authMiddleware, async (req, res) => {
    try {
        const { items, shippingAddress, paymentMethod, totalAmount } = req.body;
        
        // Validate required fields
        if (!items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ error: 'Order must contain items' });
        }

        if (!shippingAddress) {
            return res.status(400).json({ error: 'Shipping address is required' });
        }

        if (!totalAmount || totalAmount <= 0) {
            return res.status(400).json({ error: 'Invalid total amount' });
        }

        // Validate stock availability before creating order
        const stockValidationErrors = [];
        for (const item of items) {
            const medicine = await Medicine.findById(item.medicine);
            if (!medicine) {
                stockValidationErrors.push(`${item.name || 'Unknown item'}: Medicine not found`);
                continue;
            }
            
            const availableQty = (medicine.totalQty || 0) - (medicine.soldQty || 0);
            if (availableQty < item.quantity) {
                stockValidationErrors.push(`${item.name || medicine.name}: Only ${availableQty} units available, requested ${item.quantity}`);
            }
        }
        
        if (stockValidationErrors.length > 0) {
            return res.status(400).json({ 
                error: 'Insufficient stock for some items',
                details: stockValidationErrors
            });
        }

        // Generate order ID
        const orderId = 'ORD' + Date.now();
        
        // Create order with customer ID from authenticated user
        const order = new Order({
            orderId,
            customer: req.user._id, // This comes from the auth middleware
            items: items.map(item => ({
                medicine: item.medicine,
                name: item.name,
                price: item.price,
                quantity: item.quantity
            })),
            shippingAddress,
            paymentMethod,
            totalAmount,
            orderStatus: 'pending'
        });

        // Save the order
        await order.save();

        // Update medicine stock by incrementing soldQty
        for (const item of items) {
            await Medicine.findByIdAndUpdate(
                item.medicine,
                { $inc: { soldQty: item.quantity } }
            );
        }
        
        res.status(201).json({ 
            message: 'Order created successfully', 
            order: {
                orderId: order.orderId,
                totalAmount: order.totalAmount,
                orderStatus: order.orderStatus,
                items: order.items
            }
        });
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get orders for logged-in customers (SPECIFIC FOR CUSTOMER PORTAL)
app.get('/api/customer/orders', authMiddleware, async (req, res) => {
    try {
        // Only allow customers to access their own orders
        if (req.user.role !== 'customer') {
            return res.status(403).json({ error: 'Access denied. Customers only.' });
        }

        console.log('Fetching orders for customer:', req.user._id);
        
        const orders = await Order.find({ 
            customer: req.user._id 
        })
        .sort({ createdAt: -1 })
        .select('-__v') // Exclude version key
        .lean(); // Convert to plain JavaScript objects

        console.log(`Found ${orders.length} orders for customer`);

        // Format dates and ensure all required fields are present
        const formattedOrders = orders.map(order => ({
            ...order,
            createdAt: order.createdAt.toISOString(),
            updatedAt: order.updatedAt.toISOString(),
            items: order.items.map(item => ({
                ...item,
                price: Number(item.price),
                quantity: Number(item.quantity)
            })),
            totalAmount: Number(order.totalAmount)
        }));
        
        res.json(formattedOrders);
    } catch (error) {
        console.error('Error fetching customer orders:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get all orders (for admin and customers - existing route)
app.get('/api/orders', authMiddleware, async (req, res) => {
    try {
        let orders;
        if (req.user.role === 'admin') {
            orders = await Order.find()
                .populate('customer', 'name email phone')
                .sort({ createdAt: -1 });
        } else {
            orders = await Order.find({ customer: req.user._id })
                .sort({ createdAt: -1 });
        }
        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/orders/:id', authMiddleware, async (req, res) => {
    try {
        const order = await Order.findOne({ orderId: req.params.id });
        
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }

        // Check if user owns the order or is admin
        if (req.user.role !== 'admin' && order.customer && order.customer.toString() !== req.user._id.toString()) {
            return res.status(403).json({ error: 'Access denied' });
        }

        res.json(order);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/orders/:id/status', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { orderStatus } = req.body;
        const order = await Order.findOneAndUpdate(
            { orderId: req.params.id },
            { orderStatus },
            { new: true }
        );

        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }

        res.json({ message: 'Order status updated successfully', order });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Guest order tracking (no login required)
app.get('/api/orders/track/:orderId', async (req, res) => {
    try {
        const order = await Order.findOne({ orderId: req.params.orderId });
        
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }

        res.json(order);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Dashboard Stats
app.get('/api/dashboard/stats', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const totalMedicines = await Medicine.countDocuments({ isActive: true });
        const totalOrders = await Order.countDocuments();
        const totalSales = await Order.aggregate([
            { $match: { orderStatus: 'delivered' } },
            { $group: { _id: null, total: { $sum: '$totalAmount' } } }
        ]);
        const pendingOrders = await Order.countDocuments({ orderStatus: 'pending' });

        // Compute orders placed today (server local timezone)
        const startOfDay = new Date();
        startOfDay.setHours(0,0,0,0);
        const endOfDay = new Date();
        endOfDay.setHours(23,59,59,999);
        const ordersToday = await Order.countDocuments({ createdAt: { $gte: startOfDay, $lte: endOfDay } });

        res.json({
            totalMedicines,
            totalOrders,
            totalSales: totalSales[0]?.total || 0,
            pendingOrders,
            ordersToday
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Initialize Admin User
app.post('/api/init-admin', async (req, res) => {
    try {
        const adminExists = await User.findOne({ role: 'admin' });
        if (adminExists) {
            return res.status(400).json({ error: 'Admin user already exists' });
        }

        const hashedPassword = await bcrypt.hash('admin123', 10);
        const admin = new User({
            username: 'admin',
            password: hashedPassword,
            name: 'System Administrator',
            email: 'admin@anvikbiotecch.com',
            role: 'admin'
        });

        await admin.save();
        res.json({ message: 'Admin user created successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add this route to create demo customer
app.post('/api/init-demo-customer', async (req, res) => {
    try {
        const customerExists = await User.findOne({ username: 'customer' });
        if (customerExists) {
            return res.status(400).json({ error: 'Demo customer already exists' });
        }

        const hashedPassword = await bcrypt.hash('customer123', 10);
        const customer = new User({
            username: 'customer',
            password: hashedPassword,
            name: 'Demo Customer',
            email: 'customer@anvikbiotecch.com',
            phone: '9876543210',
            role: 'customer'
        });

        await customer.save();
        res.json({ message: 'Demo customer created successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📱 Frontend accessible at: http://localhost:${PORT}`);
});

// Handle server errors gracefully
server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use.`);
        console.error(`   Please either:`);
        console.error(`   1. Stop the process using port ${PORT}`);
        console.error(`   2. Use a different port by setting PORT environment variable`);
        console.error(`   3. Kill the process: taskkill /PID <process_id> /F`);
        process.exit(1);
    } else {
        console.error('❌ Server error:', err);
        process.exit(1);
    }
});

// Create Cashfree payment order and return payment link (secure, backend-only)
app.post('/api/payments/cashfree/create-order', async (req, res) => {
    try {
       
        const { items, shippingAddress, totalAmount } = req.body;

        if (!items || !Array.isArray(items) || items.length === 0)
            return res.status(400).json({ error: 'Order must contain items' });

        if (!totalAmount || totalAmount <= 0)
            return res.status(400).json({ error: 'Invalid total amount' });

        // ✅ Stock validation
        const stockValidationErrors = [];
        for (const item of items) {
            const medicine = await Medicine.findById(item.medicine);
            if (!medicine) {
                stockValidationErrors.push(`${item.name || 'Unknown item'}: Medicine not found`);
                continue;
            }
            const availableQty = (medicine.totalQty || 0) - (medicine.soldQty || 0);
            if (availableQty < item.quantity) {
                stockValidationErrors.push(`${item.name || medicine.name}: Only ${availableQty} available, requested ${item.quantity}`);
            }
        }

        // if (stockValidationErrors.length > 0)
        //     return res.status(400).json({ error: 'Insufficient stock', details: stockValidationErrors });

        // ✅ Order ID
        const orderId = "ORD" + Date.now();


        const response = await axios.post(`${process.env.DEVCRAFTOR_BASE_URL}/v2/partner/payment_links`, {
            token: process.env.DEVCRAFTOR_TOKEN,
            orderId,
            txnAmount: Number(totalAmount).toFixed(2),
            txnNote: "Order from Anvik Biotecch",
            cust_Mobile: shippingAddress?.phone || req.user?.phone || '',
            cust_Email: shippingAddress?.email || req.user?.email || '',
        },{
              headers: {
                'X-API-Key': process.env.DEVCRAFTOR_API_KEY,
                'X-API-Secret': process.env.DEVCRAFTOR_SECRET,
                'Content-Type': 'application/json',
            },
        });

        

        if (!response.data.data.paymentUrl) {
            return res.status(500).json({ error: "Failed to generate payment URL" });
        }

        // ✅ Save order in DB
        const order = new Order({
            orderId,
            items: items.map(i => ({
                medicine: i.medicine,
                name: i.name,
                price: i.price,
                quantity: i.quantity
            })),
            shippingAddress,
            paymentMethod: 'devcraftor',
            totalAmount: Number(totalAmount),
            orderStatus: 'pending',
            paymentStatus: 'pending',
            customer: req.user ? req.user._id : null,
            providerOrderId: orderId 
        });

        await order.save();

        res.status(200).json({
            success: true,
            message: "Payment order created",
            paymentLink: response.data.data.paymentUrl,
            order: {
                orderId,
                id: order._id,
                amount: order.totalAmount
            }
        });

    } catch (err) {
        console.error("DevCraftor Error", err);
        res.status(500).json({ error: err.message });
    }
});

// Cashfree webhook endpoint to receive payment notifications.
// This should be configured in Cashfree dashboard as the webhook/notify URL.
// Use raw body so we can verify signature over the exact payload bytes.
app.post('/api/payments/cashfree/webhook', bodyParser.raw({ type: '*/*' }), async (req, res) => {
    try {
        const sigHeader = req.header('x-webhook-signature') || req.header('x-cf-signature') || req.header('x-signature');
        const rawBody = req.body; // Buffer

        let payload;
        try {
            payload = JSON.parse(rawBody.toString());
        } catch (err) {
            console.error('Cashfree webhook: invalid JSON payload', err);
            return res.status(400).send('Invalid JSON');
        }

        // Verify signature if provided
        if (sigHeader) {
            const expected = crypto.createHmac('sha256', CASHFREE_SECRET).update(rawBody).digest('hex');
            if (sigHeader !== expected) {
                console.warn('Cashfree webhook signature mismatch', { received: sigHeader, expected });
                return res.status(401).send('Invalid signature');
            }
        } else {
            console.warn('Cashfree webhook: no signature header present; proceeding with caution');
        }

        console.log('Received Cashfree webhook payload:', payload);

        // Normalize fields
        const cfOrderId = payload.order_id || payload.orderId || payload.data?.order_id || payload.data?.orderId;
        const txStatus = (payload.tx_status || payload.txStatus || payload.payment_status || payload.paymentStatus || payload.data?.tx_status || payload.data?.payment_status || payload.data?.status || '').toString().toLowerCase();
        const referenceId = payload.reference_id || payload.referenceId || payload.payment_id || payload.data?.reference_id || payload.data?.payment_id || null;

        if (!cfOrderId) {
            console.warn('Cashfree webhook: missing order id');
            return res.status(400).send('Missing order id');
        }

        // Find our order by cashfreeOrderId or by orderId
        const order = await Order.findOne({ $or: [ { cashfreeOrderId: cfOrderId }, { orderId: cfOrderId } ] });
        if (!order) {
            console.warn('Cashfree webhook: local order not found for', cfOrderId);
            return res.status(404).send('Order not found');
        }

        // Map status
        const oldPaymentStatus = order.paymentStatus;
        let newPaymentStatus = order.paymentStatus;
        let newOrderStatus = order.orderStatus;

        if (['success', 'paid', 'completed'].includes(txStatus) || txStatus.includes('success')) {
            newPaymentStatus = 'completed';
            // move order to confirmed if it was pending
            if (newOrderStatus === 'pending') newOrderStatus = 'confirmed';
        } else if (['failed', 'failure', 'cancelled', 'cancel'].includes(txStatus) || txStatus.includes('fail')) {
            newPaymentStatus = 'failed';
            newOrderStatus = 'cancelled';
        } else {
            // keep as pending for other statuses
            newPaymentStatus = order.paymentStatus || 'pending';
        }

        order.paymentStatus = newPaymentStatus;
        order.orderStatus = newOrderStatus;
        if (referenceId) order.cashfreePaymentId = referenceId;

        await order.save();

        // Update stock when payment is confirmed (only once)
        if (newPaymentStatus === 'completed' && oldPaymentStatus !== 'completed') {
            // This means payment just got confirmed, update stock
            for (const item of order.items) {
                await Medicine.findByIdAndUpdate(
                    item.medicine,
                    { $inc: { soldQty: item.quantity } }
                );
            }
            console.log('Stock updated for order:', order.orderId);
        }

        console.log('Updated order after webhook:', order.orderId, order.paymentStatus, order.orderStatus);

        // Acknowledge receipt
        res.json({ ok: true });
    } catch (err) {
        console.error('Error handling Cashfree webhook:', err);
        res.status(500).send('Server error');
    }
});

// Verify order payment status (used by frontend after redirect)
app.get('/api/payments/cashfree/verify/:orderId', authMiddleware, async (req, res) => {
    try {
        const { orderId } = req.params;
        const order = await Order.findOne({ orderId });
        if (!order) return res.status(404).json({ error: 'Order not found' });

        // If payment already completed in DB, return immediately
        if (order.paymentStatus === 'completed' || order.paymentStatus === 'failed') {
            return res.json({ orderId: order.orderId, paymentStatus: order.paymentStatus, orderStatus: order.orderStatus });
        }

        // Otherwise, attempt to fetch status from Cashfree if we have a cashfreeOrderId
        if (!order.cashfreeOrderId) {
            return res.json({ orderId: order.orderId, paymentStatus: order.paymentStatus || 'pending', orderStatus: order.orderStatus });
        }

        // Call Cashfree to get latest status
        let statusResp;
        try {
            statusResp = await fetchFn(`${CASHFREE_BASE}/orders/${order.cashfreeOrderId}`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'x-client-id': CASHFREE_APP_ID,
                    'x-client-secret': CASHFREE_SECRET,
                    'x-api-version': '2022-09-01'
                }
            });
        } catch (netErr) {
            console.error('Network error while verifying Cashfree order:', netErr);
            return res.status(502).json({ error: 'Payment gateway network error', details: String(netErr) });
        }

        let statusJson;
        try {
            statusJson = await statusResp.json();
        } catch (err) {
            const raw = await statusResp.text().catch(() => '<unreadable>');
            console.error('Failed to parse Cashfree status response', err, raw);
            return res.status(502).json({ error: 'Invalid response from payment gateway', details: raw });
        }

        // Inspect returned fields
        const cfData = statusJson.data || statusJson;
        const cfStatus = (cfData.order_status || cfData.status || cfData.payment_status || '').toString().toLowerCase();

        if (cfStatus.includes('paid') || cfStatus.includes('success') || cfStatus.includes('completed')) {
            order.paymentStatus = 'completed';
            if (order.orderStatus === 'pending') order.orderStatus = 'confirmed';
        } else if (cfStatus.includes('failed') || cfStatus.includes('cancel')) {
            order.paymentStatus = 'failed';
            order.orderStatus = 'cancelled';
        }

        await order.save();

        return res.json({ orderId: order.orderId, paymentStatus: order.paymentStatus, orderStatus: order.orderStatus, cfResponse: statusJson });
    } catch (err) {
        console.error('Error verifying cashfree order:', err);
        return res.status(500).json({ error: err.message });
    }
});

// Ensure the order success page is directly reachable (helps when static middleware misses it)
app.get('/customer/order-success.html', (req, res) => {
    try {
        res.sendFile(path.join(__dirname, '..', 'customer', 'order-success.html'));
    } catch (err) {
        console.error('Error sending order-success file:', err);
        res.status(500).send('Server error');
    }
});
