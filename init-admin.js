const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// MongoDB Connection
const MONGODB_URI = 'mongodb+srv://chandan:6QJ8O1GihYgEotag@store.plmwltk.mongodb.net/anvik-biotecch?retryWrites=true&w=majority';

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB Atlas'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'customer'], default: 'customer' },
    name: String,
    email: String,
    phone: String
});

const User = mongoose.model('User', userSchema);

async function createAdmin() {
    try {
        // Check if admin exists
        const adminExists = await User.findOne({ role: 'admin' });
        if (adminExists) {
            console.log('Admin user already exists');
            process.exit(0);
        }

        // Create admin user
        const hashedPassword = await bcrypt.hash('admin123', 10);
        const admin = new User({
            username: 'admin',
            password: hashedPassword,
            name: 'System Administrator',
            email: 'admin@anvikbiotecch.com',
            role: 'admin'
        });

        await admin.save();
        console.log('✅ Admin user created successfully');
        console.log('Username: admin');
        console.log('Password: admin123');
    } catch (error) {
        console.error('Error creating admin:', error);
    } finally {
        process.exit(0);
    }
}

createAdmin();