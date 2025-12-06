import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { GoogleGenAI } from '@google/genai';

// ============================================================================
// CONFIGURATION
// ============================================================================
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_123';

// Increase payload limit for Base64 image uploads
app.use(express.json({ limit: '50mb' }));
app.use(cors());

// Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Gemini AI Client
const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

// ============================================================================
// 🚨 DATABASE SETUP ROUTE (MOVED TO TOP - RUN ONCE)
// ============================================================================
app.get('/api/setup-db', async (req, res) => {
    try {
        await pool.query(`
            CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

            CREATE TABLE IF NOT EXISTS users (
                id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'client',
                is_admin BOOLEAN DEFAULT FALSE,
                admin_role TEXT,
                is_suspended BOOLEAN DEFAULT FALSE,
                phone_number TEXT,
                state TEXT, city TEXT, address TEXT,
                profile_photo TEXT, bio TEXT,
                cleaner_type TEXT, company_name TEXT, experience INTEGER, services TEXT,
                charge_hourly NUMERIC, charge_daily NUMERIC, charge_per_contract NUMERIC,
                bank_name TEXT, account_number TEXT,
                government_id TEXT, business_reg_doc TEXT,
                subscription_tier TEXT DEFAULT 'Free',
                pending_subscription TEXT,
                subscription_receipt TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS bookings (
                id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
                client_id UUID REFERENCES users(id),
                cleaner_id UUID REFERENCES users(id),
                client_name TEXT, cleaner_name TEXT, service TEXT,
                date DATE, amount NUMERIC, total_amount NUMERIC,
                payment_method TEXT, status TEXT DEFAULT 'Upcoming', payment_status TEXT,
                job_approved_by_client BOOLEAN DEFAULT FALSE, review_submitted BOOLEAN DEFAULT FALSE,
                payment_receipt TEXT, created_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS reviews (
                id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
                booking_id UUID REFERENCES bookings(id),
                cleaner_id UUID REFERENCES users(id),
                reviewer_name TEXT, rating NUMERIC, timeliness NUMERIC, thoroughness NUMERIC, conduct NUMERIC, comment TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS chats (
                id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
                participant_one UUID REFERENCES users(id),
                participant_two UUID REFERENCES users(id),
                last_message_id UUID,
                updated_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS messages (
                id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
                chat_id UUID REFERENCES chats(id),
                sender_id UUID REFERENCES users(id),
                text TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);
        res.send("Database tables created successfully! Go back and Register.");
    } catch (error) {
        console.error(error);
        res.status(500).send("Error creating tables: " + error.message);
    }
});

// ============================================================================
// UTILITIES
// ============================================================================
const generateToken = (id, role, isAdmin, adminRole) => {
  return jwt.sign({ id, role, isAdmin, adminRole }, JWT_SECRET, { expiresIn: '30d' });
};

const sendEmail = async (to, subject, text) => {
  if (process.env.NODE_ENV !== 'test') {
    console.log(`\n--- [MOCK EMAIL] ---\nTo: ${to}\nSubject: ${subject}\nBody: ${text}\n--------------------\n`);
  }
};

const handleError = (res, error, message = 'Server Error') => {
  console.error(message, error);
  res.status(500).json({ message: error.message || message });
};

// ============================================================================
// MIDDLEWARE
// ============================================================================
const protect = (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      next();
    } catch (error) {
      res.status(401).json({ message: 'Not authorized, token failed' });
    }
  } else {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

const admin = (req, res, next) => {
  if (req.user && req.user.isAdmin) next();
  else res.status(403).json({ message: 'Admin access required' });
};

// ============================================================================
// ROUTES: AUTH
// ============================================================================
app.post('/api/auth/register', async (req, res) => {
  const { email, password, role, fullName, phoneNumber, state, city, address, clientType, cleanerType, companyName, experience, services, bio, chargeHourly, chargeDaily, chargePerContract, bankName, accountNumber, profilePhoto, governmentId, businessRegDoc } = req.body;

  try {
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) return res.status(400).json({ message: 'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const servicesJson = services ? JSON.stringify(services) : null; 

    const result = await pool.query(
      `INSERT INTO users (
        email, password_hash, role, full_name, phone_number, state, city, address, 
        client_type, cleaner_type, company_name, experience, services, bio, 
        charge_hourly, charge_daily, charge_per_contract, bank_name, account_number,
        profile_photo, government_id, business_reg_doc, subscription_tier, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, 'Free', NOW()) RETURNING *`,
      [email, hashedPassword, role, fullName, phoneNumber, state, city, address, clientType, cleanerType, companyName, experience, servicesJson, bio, chargeHourly, chargeDaily, chargePerContract, bankName, accountNumber, profilePhoto, governmentId, businessRegDoc]
    );

    const user = result.rows[0];
    res.status(201).json({
      ...user,
      token: generateToken(user.id, user.role, user.is_admin, user.admin_role)
    });
  } catch (error) { handleError(res, error, 'Registration failed'); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (user && (await bcrypt.compare(password, user.password_hash))) {
      if (user.is_suspended) return res.status(403).json({ message: 'Account is suspended.' });
      
      const userData = {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        role: user.role,
        isAdmin: user.is_admin,
        adminRole: user.admin_role,
        profilePhoto: user.profile_photo,
        subscriptionTier: user.subscription_tier,
      };
      
      res.json({ token: generateToken(user.id, user.role, user.is_admin, user.admin_role), user: userData });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) { handleError(res, error, 'Login failed'); }
});

// ============================================================================
// ROUTES: USERS & CLEANERS
// ============================================================================
app.get('/api/users/me', protect, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.*, 
        (SELECT json_agg(b.*) FROM bookings b WHERE b.client_id = u.id OR b.cleaner_id = u.id) as booking_history,
        (SELECT json_agg(r.*) FROM reviews r WHERE r.cleaner_id = u.id) as reviews_data
      FROM users u WHERE u.id = $1
    `, [req.user.id]);
    
    const user = result.rows[0];
    if (!user) return res.status(404).json({ message: 'User not found' });

    const formattedUser = {
      id: user.id,
      fullName: user.full_name,
      email: user.email,
      role: user.role,
      phoneNumber: user.phone_number,
      address: user.address,
      state: user.state,
      city: user.city,
      profilePhoto: user.profile_photo,
      isAdmin: user.is_admin,
      adminRole: user.admin_role,
      subscriptionTier: user.subscription_tier,
      cleanerType: user.cleaner_type,
      clientType: user.client_type,
      experience: user.experience,
      bio: user.bio,
      services: typeof user.services === 'string' ? JSON.parse(user.services) : user.services,
      chargeHourly: user.charge_hourly,
      chargeDaily: user.charge_daily,
      chargePerContract: user.charge_per_contract,
      bankName: user.bank_name,
      accountNumber: user.account_number,
      bookingHistory: user.booking_history || [],
      reviewsData: user.reviews_data || [],
      pendingSubscription: user.pending_subscription,
      subscriptionReceipt: user.subscription_receipt ? JSON.parse(user.subscription_receipt) : null
    };

    res.json(formattedUser);
  } catch (error) { handleError(res, error); }
});

app.put('/api/users/me', protect, async (req, res) => {
  const { fullName, phoneNumber, address, bio, services, experience, chargeHourly, chargeDaily, chargePerContract, profilePhoto } = req.body;
  try {
    const result = await pool.query(
      `UPDATE users SET 
        full_name = COALESCE($1, full_name),
        phone_number = COALESCE($2, phone_number),
        address = COALESCE($3, address),
        bio = COALESCE($4, bio),
        services = COALESCE($5, services),
        experience = COALESCE($6, experience),
        charge_hourly = COALESCE($7, charge_hourly),
        charge_daily = COALESCE($8, charge_daily),
        charge_per_contract = COALESCE($9, charge_per_contract),
        profile_photo = COALESCE($10, profile_photo)
       WHERE id = $11 RETURNING *`,
      [fullName, phoneNumber, address, bio, JSON.stringify(services), experience, chargeHourly, chargeDaily, chargePerContract, profilePhoto, req.user.id]
    );
    res.json(result.rows[0]); 
  } catch (error) { handleError(res, error, 'Update failed'); }
});

app.get('/api/cleaners', async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE role = 'cleaner' AND is_suspended = false");
    const cleaners = result.rows.map(c => ({
      id: c.id,
      name: c.full_name,
      photoUrl: c.profile_photo,
      rating: 5.0, 
      reviews: 0,
      serviceTypes: typeof c.services === 'string' ? JSON.parse(c.services) : (c.services || []),
      state: c.state,
      city: c.city,
      experience: c.experience,
      bio: c.bio,
      isVerified: !!c.business_reg_doc,
      chargeHourly: c.charge_hourly,
      subscriptionTier: c.subscription_tier,
      cleanerType: c.cleaner_type
    }));
    res.json(cleaners);
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: BOOKINGS
// ============================================================================
app.post('/api/bookings', protect, async (req, res) => {
  const { cleanerId, service, date, amount, totalAmount, paymentMethod } = req.body;
  try {
    const cleanerRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [cleanerId]);
    const cleanerName = cleanerRes.rows[0]?.full_name || 'Cleaner';
    
    const clientRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [req.user.id]);
    const clientName = clientRes.rows[0]?.full_name || 'Client';

    const result = await pool.query(
      `INSERT INTO bookings (
        client_id, cleaner_id, client_name, cleaner_name, service, date, amount, total_amount, payment_method, status, payment_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'Upcoming', $10, NOW()) RETURNING *`,
      [req.user.id, cleanerId, clientName, cleanerName, service, date, amount, totalAmount, paymentMethod, paymentMethod === 'Direct' ? 'Not Applicable' : 'Pending Payment']
    );

    await sendEmail(req.user.id, 'Booking Confirmation', `You booked ${cleanerName} for ${service}.`);
    res.status(201).json(result.rows[0]);
  } catch (error) { handleError(res, error, 'Booking failed'); }
});

app.post('/api/bookings/:id/cancel', protect, async (req, res) => {
  try {
    const result = await pool.query("UPDATE bookings SET status = 'Cancelled' WHERE id = $1 RETURNING *", [req.params.id]);
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error); }
});

app.post('/api/bookings/:id/complete', protect, async (req, res) => {
  try {
    const bookingRes = await pool.query('SELECT * FROM bookings WHERE id = $1', [req.params.id]);
    const booking = bookingRes.rows[0];
    
    let newPaymentStatus = booking.payment_status;
    if (booking.payment_method === 'Escrow' && booking.payment_status === 'Confirmed') {
      newPaymentStatus = 'Pending Payout';
    }

    const result = await pool.query(
      "UPDATE bookings SET status = 'Completed', job_approved_by_client = true, payment_status = $1 WHERE id = $2 RETURNING *", 
      [newPaymentStatus, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error); }
});

app.post('/api/bookings/:id/review', protect, async (req, res) => {
  const { rating, timeliness, thoroughness, conduct, comment, cleanerId } = req.body;
  try {
    const clientRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [req.user.id]);
    const reviewerName = clientRes.rows[0]?.full_name || 'Anonymous';

    await pool.query(
      `INSERT INTO reviews (booking_id, cleaner_id, reviewer_name, rating, timeliness, thoroughness, conduct, comment, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
      [req.params.id, cleanerId, reviewerName, rating, timeliness, thoroughness, conduct, comment]
    );
    
    await pool.query("UPDATE bookings SET review_submitted = true WHERE id = $1", [req.params.id]);
    res.json({ message: 'Review submitted' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/bookings/:id/receipt', protect, async (req, res) => {
  const { name, dataUrl } = req.body;
  try {
    const receiptJson = JSON.stringify({ name, dataUrl });
    const result = await pool.query(
      "UPDATE bookings SET payment_receipt = $1, payment_status = 'Pending Admin Confirmation' WHERE id = $2 RETURNING *",
      [receiptJson, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: SUBSCRIPTION
// ============================================================================
app.post('/api/users/subscription/upgrade', protect, async (req, res) => {
  const { plan } = req.body;
  try {
    const result = await pool.query(
      "UPDATE users SET pending_subscription = $1 WHERE id = $2 RETURNING *",
      [plan, req.user.id]
    );
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error); }
});

app.post('/api/users/subscription/receipt', protect, async (req, res) => {
  const { name, dataUrl } = req.body;
  try {
    const receiptJson = JSON.stringify({ name, dataUrl });
    const result = await pool.query(
      "UPDATE users SET subscription_receipt = $1 WHERE id = $2 RETURNING *",
      [receiptJson, req.user.id]
    );
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: ADMIN
// ============================================================================
app.get('/api/admin/users', protect, admin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users ORDER BY created_at DESC');
    res.json(result.rows.map(u => ({
        id: u.id,
        fullName: u.full_name,
        email: u.email,
        role: u.role,
        isAdmin: u.is_admin,
        isSuspended: u.is_suspended,
        subscriptionTier: u.subscription_tier,
        pendingSubscription: u.pending_subscription,
        subscriptionReceipt: u.subscription_receipt ? JSON.parse(u.subscription_receipt) : null,
        bookingHistory: []
    })));
  } catch (error) { handleError(res, error); }
});

app.patch('/api/admin/users/:id/status', protect, admin, async (req, res) => {
  const { isSuspended } = req.body;
  try {
    await pool.query('UPDATE users SET is_suspended = $1 WHERE id = $2', [isSuspended, req.params.id]);
    res.json({ message: 'User status updated' });
  } catch (error) { handleError(res, error); }
});

app.delete('/api/admin/users/:id', protect, admin, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ message: 'User deleted' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/bookings/:id/confirm-payment', protect, admin, async (req, res) => {
  try {
    await pool.query("UPDATE bookings SET payment_status = 'Confirmed' WHERE id = $1", [req.params.id]);
    res.json({ message: 'Payment confirmed' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/bookings/:id/mark-paid', protect, admin, async (req, res) => {
  try {
    await pool.query("UPDATE bookings SET payment_status = 'Paid' WHERE id = $1", [req.params.id]);
    res.json({ message: 'Marked as paid' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/users/:id/approve-subscription', protect, admin, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT pending_subscription FROM users WHERE id = $1', [req.params.id]);
    const plan = userRes.rows[0]?.pending_subscription;
    if (!plan) return res.status(400).json({ message: 'No pending subscription' });

    await pool.query(
      "UPDATE users SET subscription_tier = $1, pending_subscription = NULL, subscription_receipt = NULL WHERE id = $2",
      [plan, req.params.id]
    );
    res.json({ message: 'Subscription approved' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/create-admin', protect, admin, async (req, res) => {
  const { fullName, email, password, role } = req.body;
  try {
     const salt = await bcrypt.genSalt(10);
     const hashedPassword = await bcrypt.hash(password, salt);
     const result = await pool.query(
         `INSERT INTO users (full_name, email, password_hash, role, is_admin, admin_role, created_at)
          VALUES ($1, $2, $3, 'admin', true, $4, NOW()) RETURNING *`,
         [fullName, email, hashedPassword, role]
     );
     res.status(201).json(result.rows[0]);
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: CHAT
// ============================================================================
app.post('/api/chats', protect, async (req, res) => {
    const { participantId } = req.body;
    const userId = req.user.id;

    try {
        const existingChat = await pool.query(
            `SELECT * FROM chats WHERE (participant_one = $1 AND participant_two = $2) OR (participant_one = $2 AND participant_two = $1)`,
            [userId, participantId]
        );

        if (existingChat.rows.length > 0) {
            return res.json({ id: existingChat.rows[0].id, participants: [existingChat.rows[0].participant_one, existingChat.rows[0].participant_two], participantNames: {} }); 
        }

        const result = await pool.query(
            'INSERT INTO chats (participant_one, participant_two) VALUES ($1, $2) RETURNING *',
            [userId, participantId]
        );
        res.status(201).json({ id: result.rows[0].id, participants: [userId, participantId], participantNames: {} });
    } catch (error) { handleError(res, error, 'Failed to create chat'); }
});

app.get('/api/chats', protect, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT c.*, 
                    m.text as last_message_text, 
                    m.sender_id as last_message_sender, 
                    m.created_at as last_message_time,
                    u1.full_name as name1, u2.full_name as name2
             FROM chats c
             LEFT JOIN messages m ON c.last_message_id = m.id
             JOIN users u1 ON c.participant_one = u1.id
             JOIN users u2 ON c.participant_two = u2.id
             WHERE c.participant_one = $1 OR c.participant_two = $1
             ORDER BY m.created_at DESC NULLS LAST`,
            [req.user.id]
        );

        const chats = result.rows.map(row => ({
            id: row.id,
            participants: [row.participant_one, row.participant_two],
            participantNames: {
                [row.participant_one]: row.name1,
                [row.participant_two]: row.name2
            },
            lastMessage: row.last_message_text ? {
                text: row.last_message_text,
                senderId: row.last_message_sender,
                timestamp: row.last_message_time
            } : undefined,
            updatedAt: row.last_message_time || row.created_at
        }));
        res.json(chats);
    } catch (error) { handleError(res, error); }
});

app.get('/api/chats/:id/messages', protect, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM messages WHERE chat_id = $1 ORDER BY created_at ASC',
            [req.params.id]
        );
        const messages = result.rows.map(r => ({
            id: r.id,
            chatId: r.chat_id,
            senderId: r.sender_id,
            text: r.text,
            timestamp: r.created_at
        }));
        res.json(messages);
    } catch (error) { handleError(res, error); }
});

app.post('/api/chats/:id/messages', protect, async (req, res) => {
    const { text } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO messages (chat_id, sender_id, text) VALUES ($1, $2, $3) RETURNING *',
            [req.params.id, req.user.id, text]
        );
        const message = result.rows[0];
        
        await pool.query('UPDATE chats SET last_message_id = $1, updated_at = NOW() WHERE id = $2', [message.id, req.params.id]);

        res.status(201).json({
            id: message.id,
            chatId: message.chat_id,
            senderId: message.sender_id,
            text: message.text,
            timestamp: message.created_at
        });
    } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: AI & MISC
// ============================================================================
app.post('/api/search/ai', async (req, res) => {
  const { query } = req.body;
  try {
    const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: `You are a helper for a cleaning service app in Nigeria. 
        Extract key search terms (location, service type, budget) from this user query: "${query}".
        Return ONLY a JSON object with keys: "location" (string), "service" (string), "maxPrice" (number). 
        If info is missing, use null.
        Example: {"location": "Lagos", "service": "Deep Cleaning", "maxPrice": 50000}`
    });
    
    const text = response.text;
    if (!text) throw new Error("No response from AI");
    const cleanJson = text.replace(/```json|```/g, '').trim();
    const criteria = JSON.parse(cleanJson);

    let sql = "SELECT id FROM users WHERE role = 'cleaner'";
    const params = [];
    let paramIndex = 1;

    if (criteria.location) {
        sql += ` AND (city ILIKE $${paramIndex} OR state ILIKE $${paramIndex})`;
        params.push(`%${criteria.location}%`);
        paramIndex++;
    }

    const result = await pool.query(sql, params);
    res.json({ matchingIds: result.rows.map(r => r.id) });

  } catch (error) { 
      console.error(error);
      res.json({ matchingIds: [] });
  }
});

app.post('/api/contact', (req, res) => {
    console.log('Contact Form:', req.body);
    res.json({ message: 'Message received' });
});

// ============================================================================
// SERVER START (Modified for Vercel + ES Modules)
// ============================================================================

// 1. Keep your 404 Handler (MUST BE LAST)
app.use((req, res, next) => {
    res.status(404).json({ message: `Not Found - ${req.originalUrl}` });
});

// 2. Only "listen" on a port if we are running LOCALLY
if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

// 3. Export the app
export default app;