import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { GoogleGenAI } from '@google/genai';

// ============================================================================
// 1. CONFIGURATION
// ============================================================================
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_123';

// Increase payload limit for Base64 image uploads (Receipts/Profiles)
app.use(express.json({ limit: '50mb' }));
app.use(cors());

// Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Gemini AI Client
const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

// TypeScript Interface for Auth
interface AuthRequest extends Request {
  user?: { id: string; role: string; isAdmin: boolean; adminRole?: string; };
}

// ============================================================================
// 2. UTILITIES
// ============================================================================
const generateToken = (id: string, role: string, isAdmin: boolean, adminRole?: string) => {
  return jwt.sign({ id, role, isAdmin, adminRole }, JWT_SECRET, { expiresIn: '30d' });
};

const sendEmail = async (to: string, subject: string, text: string) => {
  // Production-ready email logic would go here (e.g., SendGrid, Nodemailer)
  if (process.env.NODE_ENV !== 'test') console.log(`[EMAIL MOCK] To: ${to} | Subject: ${subject}`);
};

const handleError = (res: Response, error: any, message: string = 'Server Error') => {
  console.error(message, error);
  // Improved error message for production, but keeps internal error for dev/console
  const status = error.name === 'JsonWebTokenError' ? 401 : 500;
  res.status(status).json({ message: error.message || message });
};

// ============================================================================
// 3. MIDDLEWARE
// ============================================================================
const protect = (req: Request, res: Response, next: NextFunction) => {
  let token;
  if (req.headers.authorization?.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      (req as AuthRequest).user = decoded;
      next();
    } catch (error) {
      // Specifically handle JWT errors which result in 401
      handleError(res, error, 'Not authorized, token failed');
    }
  } else {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

const admin = (req: Request, res: Response, next: NextFunction) => {
  const authReq = req as AuthRequest;
  if (authReq.user && authReq.user.isAdmin) {
    next();
  } else {
    res.status(403).json({ message: 'Admin access required' });
  }
};

// ============================================================================
// 4. DATABASE SETUP (Run Once)
// ============================================================================
app.get('/api/setup-db', async (req: Request, res: Response) => {
    try {
        await pool.query(`
            CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

            -- Table: users (Added client_type for better segregation)
            CREATE TABLE IF NOT EXISTS users (
                id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'client', -- 'client' or 'cleaner'
                is_admin BOOLEAN DEFAULT FALSE,
                admin_role TEXT,
                is_suspended BOOLEAN DEFAULT FALSE,
                
                -- Contact
                phone_number TEXT,
                state TEXT, city TEXT, address TEXT,
                
                -- Profile
                profile_photo TEXT, bio TEXT,
                
                -- Cleaner Specific
                cleaner_type TEXT, company_name TEXT, experience INTEGER, services TEXT,
                charge_hourly NUMERIC, charge_daily NUMERIC, charge_per_contract NUMERIC,
                
                -- Client Specific
                client_type TEXT, -- Added: 'Residential', 'Commercial'
                
                -- Financial/Verification
                bank_name TEXT, account_number TEXT,
                government_id TEXT, business_reg_doc TEXT,
                
                -- Subscriptions
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
                date DATE, time TEXT DEFAULT '09:00 AM',
                amount NUMERIC, total_amount NUMERIC,
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

            -- Ensure numeric types are set correctly
            ALTER TABLE reviews ALTER COLUMN rating TYPE NUMERIC;
            ALTER TABLE reviews ALTER COLUMN timeliness TYPE NUMERIC;
            ALTER TABLE reviews ALTER COLUMN thoroughness TYPE NUMERIC;
            ALTER TABLE reviews ALTER COLUMN conduct TYPE NUMERIC;
        `);
        res.send("Database tables created and updated successfully!");
    } catch (error: any) {
        console.error(error);
        res.status(500).send("Error creating tables: " + error.message);
    }
});

// ============================================================================
// 5. ADMIN ROUTES
// ============================================================================

// GET ALL BOOKINGS 
app.get('/api/admin/bookings', protect, admin, async (req: Request, res: Response) => {
    try {
        const result = await pool.query(`
            SELECT 
                id, client_name, cleaner_name, service, amount, total_amount, 
                status, payment_status, payment_method, payment_receipt, 
                to_char(date, 'YYYY-MM-DD') as formatted_date, time
            FROM bookings 
            ORDER BY created_at DESC
        `);

        const bookings = result.rows.map(b => {
            let receipt = null;
            try {
                if (b.payment_receipt) {
                    // Handle potential empty string/object from DB
                    receipt = typeof b.payment_receipt === 'string' ? JSON.parse(b.payment_receipt) : b.payment_receipt;
                }
            } catch (e) { console.error("Receipt parse error", e); }

            return {
                id: b.id,
                clientName: b.client_name || 'Unknown',
                cleanerName: b.cleaner_name || 'Unknown',
                service: b.service,
                amount: parseFloat(b.amount || '0'),
                totalAmount: parseFloat(b.total_amount || '0'),
                status: b.status,
                paymentStatus: b.payment_status,
                paymentMethod: b.payment_method,
                date: b.formatted_date,
                time: b.time,
                paymentReceipt: receipt
            };
        });
        res.json(bookings);
    } catch (error) { handleError(res, error, 'Failed to fetch admin bookings'); }
});

// GET ALL USERS (Fixed to include client_type)
app.get('/api/admin/users', protect, admin, async (req: Request, res: Response) => {
  try {
    const result = await pool.query('SELECT * FROM users ORDER BY created_at DESC');

    const users = result.rows.map(u => ({
        id: u.id, 
        fullName: u.full_name, 
        email: u.email, 
        role: u.role, 
        phoneNumber: u.phone_number || 'N/A', 
        address: u.address || 'N/A',
        city: u.city || '',
        state: u.state || '',
        profilePhoto: u.profile_photo,
        bio: u.bio,
        experience: u.experience,
        // Bank Details
        bankName: u.bank_name || 'N/A',
        accountNumber: u.account_number || 'N/A',
        // Rates
        chargeHourly: u.charge_hourly,
        chargeDaily: u.charge_daily,
        chargePerContract: u.charge_per_contract,
        cleanerType: u.cleaner_type,
        clientType: u.client_type, // Added
        // Admin flags
        isAdmin: u.is_admin, 
        isSuspended: u.is_suspended, 
        adminRole: u.admin_role,
        subscriptionTier: u.subscription_tier, 
        pendingSubscription: u.pending_subscription, 
        subscriptionReceipt: u.subscription_receipt ? JSON.parse(u.subscription_receipt) : null, 
        bookingHistory: []
    }));
    res.json(users);
  } catch (error) { handleError(res, error, 'Failed to fetch admin users'); }
});

// GET USER DETAILS (For Modal)
app.get('/api/admin/users/:id/details', protect, admin, async (req: Request, res: Response) => {
    try {
        const bookingsRes = await pool.query(`
            SELECT id, service, amount, status, payment_status, payment_receipt, client_name, cleaner_name, to_char(date, 'YYYY-MM-DD') as date 
            FROM bookings 
            WHERE client_id = $1 OR cleaner_id = $1 
            ORDER BY created_at DESC
        `, [req.params.id]);

        const history = bookingsRes.rows.map(b => ({
            ...b,
            paymentReceipt: b.payment_receipt && b.payment_receipt !== '{}' ? (typeof b.payment_receipt === 'string' ? JSON.parse(b.payment_receipt) : b.payment_receipt) : null
        }));
        res.json(history);
    } catch (error) { handleError(res, error, 'Failed to fetch user booking details'); }
});

// ADMIN ACTIONS
app.post('/api/admin/bookings/:id/confirm-payment', protect, admin, async (req: Request, res: Response) => {
  try {
    await pool.query("UPDATE bookings SET payment_status = 'Confirmed' WHERE id = $1", [req.params.id]);
    res.json({ message: 'Payment confirmed successfully' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/bookings/:id/mark-paid', protect, admin, async (req: Request, res: Response) => {
  try {
    await pool.query("UPDATE bookings SET payment_status = 'Paid' WHERE id = $1", [req.params.id]);
    res.json({ message: 'Marked as paid' });
  } catch (error) { handleError(res, error); }
});

app.patch('/api/admin/users/:id/status', protect, admin, async (req: Request, res: Response) => {
  try {
    await pool.query('UPDATE users SET is_suspended = $1 WHERE id = $2', [req.body.isSuspended, req.params.id]);
    res.json({ message: 'User status updated' });
  } catch (error) { handleError(res, error); }
});

app.delete('/api/admin/users/:id', protect, admin, async (req: Request, res: Response) => {
  try {
    // Cascade delete is generally safer for primary user data
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ message: 'User deleted' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/create-admin', protect, admin, async (req: Request, res: Response) => {
  const { fullName, email, password, role } = req.body;
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const result = await pool.query(
        `INSERT INTO users (full_name, email, password_hash, role, is_admin, admin_role, created_at) 
         VALUES ($1, $2, $3, 'admin', true, $4, NOW()) RETURNING *`, [fullName, email, hashedPassword, role]
      );
      // Remove hash before returning
      const { password_hash, ...adminUser } = result.rows[0];
      res.status(201).json(adminUser);
  } catch (error) { handleError(res, error, 'Failed to create admin'); }
});

app.post('/api/admin/users/:id/approve-subscription', protect, admin, async (req: Request, res: Response) => {
  try {
    const userRes = await pool.query('SELECT pending_subscription FROM users WHERE id = $1', [req.params.id]);
    const plan = userRes.rows[0]?.pending_subscription;
    if (!plan) return res.status(400).json({ message: 'No pending subscription' });
    await pool.query("UPDATE users SET subscription_tier = $1, pending_subscription = NULL, subscription_receipt = NULL WHERE id = $2", [plan, req.params.id]);
    res.json({ message: 'Subscription approved' });
  } catch (error) { handleError(res, error, 'Failed to approve subscription'); }
});

// ============================================================================
// 6. CLIENT & CLEANER ROUTES
// ============================================================================

// GET USER PROFILE (With Photos & Names)
app.get('/api/users/me', protect, async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  try {
    const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [authReq.user!.id]);
    const user = userRes.rows[0];
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Join with Users table to get Cleaner Photo & Real Name
    const bookingsRes = await pool.query(`
        SELECT 
            b.id, b.service, b.status, b.amount, b.total_amount, b.payment_method, b.payment_status, 
            b.cleaner_id, b.client_id, b.time, b.job_approved_by_client, b.review_submitted,
            to_char(b.date, 'YYYY-MM-DD') as formatted_date, 
            u.full_name as cleaner_real_name,
            u.profile_photo as cleaner_photo,
            c.full_name as client_real_name
        FROM bookings b 
        LEFT JOIN users u ON b.cleaner_id = u.id
        LEFT JOIN users c ON b.client_id = c.id
        WHERE b.client_id = $1 OR b.cleaner_id = $1 
        ORDER BY b.created_at DESC
    `, [authReq.user!.id]);

    const formattedBookings = bookingsRes.rows.map(b => ({
        id: b.id, 
        date: b.formatted_date, 
        time: b.time || '09:00 AM', 
        service: b.service, 
        status: b.status, 
        amount: parseFloat(b.amount || '0'), 
        totalAmount: parseFloat(b.total_amount || '0'), 
        paymentMethod: b.payment_method, 
        paymentStatus: b.payment_status, 
        cleanerId: b.cleaner_id, 
        clientId: b.client_id, 
        cleanerName: b.cleaner_real_name || b.cleaner_name || 'Cleaner',
        clientName: b.client_real_name || b.client_name || 'Client',
        cleanerPhoto: b.cleaner_photo, 
        reviewSubmitted: b.review_submitted, 
        jobApprovedByClient: b.job_approved_by_client
    }));

    // Remove hash from returned user object
    const { password_hash, ...safeUser } = user;

    const formattedUser = {
      ...safeUser,
      fullName: user.full_name,
      // Ensure all numeric fields are parsed correctly
      chargeHourly: parseFloat(user.charge_hourly || 0), 
      chargeDaily: parseFloat(user.charge_daily || 0), 
      chargePerContract: parseFloat(user.charge_per_contract || 0),
      // Ensure JSON fields are parsed correctly
      services: typeof user.services === 'string' && user.services ? JSON.parse(user.services) : user.services,
      subscriptionReceipt: user.subscription_receipt ? JSON.parse(user.subscription_receipt) : null,
      bookingHistory: formattedBookings, 
    };
    res.json(formattedUser);
  } catch (error) { handleError(res, error, 'Failed to fetch user profile'); }
});

// UPDATE PROFILE
app.put('/api/users/me', protect, async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  const { fullName, phoneNumber, address, city, state, bio, services, experience, chargeHourly, chargeDaily, chargePerContract, bankName, accountNumber, profilePhoto } = req.body;
  try {
    const result = await pool.query(
      `UPDATE users SET 
        full_name = COALESCE($1, full_name), 
        phone_number = COALESCE($2, phone_number), 
        address = COALESCE($3, address), 
        city = COALESCE($4, city),
        state = COALESCE($5, state),
        bio = COALESCE($6, bio), 
        services = COALESCE($7::jsonb, services), -- Use ::jsonb to ensure correct type if value is JSON string
        experience = COALESCE($8, experience), 
        charge_hourly = COALESCE($9, charge_hourly), 
        charge_daily = COALESCE($10, charge_daily), 
        charge_per_contract = COALESCE($11, charge_per_contract), 
        bank_name = COALESCE($12, bank_name),
        account_number = COALESCE($13, account_number),
        profile_photo = COALESCE($14, profile_photo) 
        WHERE id = $15 RETURNING *`, 
      [fullName, phoneNumber, address, city, state, bio, JSON.stringify(services), experience, chargeHourly, chargeDaily, chargePerContract, bankName, accountNumber, profilePhoto, authReq.user!.id]
    );

    // Remove hash before returning
    const { password_hash, ...updatedUser } = result.rows[0];
    res.json(updatedUser); 
  } catch (error) { handleError(res, error, 'Update failed'); }
});

// GET CLEANERS (For Search - With Review Count)
app.get('/api/cleaners', async (req: Request, res: Response) => {
  try {
    const result = await pool.query(`
        SELECT u.*, COALESCE(AVG(r.rating), 5.0) as avg_rating, COUNT(r.id) as review_count
        FROM users u LEFT JOIN reviews r ON u.id = r.cleaner_id
        WHERE u.role = 'cleaner' AND u.is_suspended = false
        GROUP BY u.id
    `);
    const cleaners = result.rows.map(c => ({ 
        id: c.id, name: c.full_name, photoUrl: c.profile_photo, 
        rating: parseFloat(parseFloat(c.avg_rating).toFixed(1)), 
        reviews: parseInt(c.review_count), 
        serviceTypes: typeof c.services === 'string' ? JSON.parse(c.services) : (c.services || []), 
        state: c.state, city: c.city, otherCity: c.city === 'Other' ? c.address : null, 
        experience: c.experience, bio: c.bio, isVerified: !!c.business_reg_doc, 
        chargeHourly: parseFloat(c.charge_hourly || '0'), 
        chargeDaily: parseFloat(c.charge_daily || '0'), 
        chargePerContract: parseFloat(c.charge_per_contract || '0'), 
        subscriptionTier: c.subscription_tier, cleanerType: c.cleaner_type 
    }));
    res.json(cleaners);
  } catch (error) { handleError(res, error, 'Failed to fetch cleaners'); }
});

// ============================================================================
// 7. BOOKING ACTION ROUTES (FIXED INSERT)
// ============================================================================
app.post('/api/bookings', protect, async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  const { cleanerId, service, date, time = '09:00 AM', amount, totalAmount, paymentMethod } = req.body;
  try {
    // 1. Get Names
    const cleanerRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [cleanerId]);
    const cleanerName = cleanerRes.rows[0]?.full_name || 'Cleaner';
    const clientRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [authReq.user!.id]);
    const clientName = clientRes.rows[0]?.full_name || 'Client';
    
    let payStatus = 'Pending Payment';
    if(paymentMethod === 'Direct') payStatus = 'Not Applicable';

    // 2. Insert with Correct Columns
    const result = await pool.query(
      `INSERT INTO bookings (
          client_id, cleaner_id, client_name, cleaner_name, service, date, time, amount, total_amount, 
          payment_method, status, payment_status, created_at
        ) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'Upcoming', $11, NOW()) 
        RETURNING *`,
      [authReq.user!.id, cleanerId, clientName, cleanerName, service, date, time, amount, totalAmount, paymentMethod, payStatus]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) { handleError(res, error, 'Booking failed'); }
});

app.post('/api/bookings/:id/cancel', protect, async (req: Request, res: Response) => {
  try {
    const result = await pool.query("UPDATE bookings SET status = 'Cancelled' WHERE id = $1 RETURNING *", [req.params.id]);
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error, 'Failed to cancel booking'); }
});

app.post('/api/bookings/:id/complete', protect, async (req: Request, res: Response) => {
  try {
    const bookingRes = await pool.query('SELECT * FROM bookings WHERE id = $1', [req.params.id]);
    const booking = bookingRes.rows[0];
    let newPaymentStatus = booking.payment_status;
    if (booking.payment_method === 'Escrow' && booking.payment_status === 'Confirmed') newPaymentStatus = 'Pending Payout';
    
    const result = await pool.query("UPDATE bookings SET status = 'Completed', job_approved_by_client = true, payment_status = $1 WHERE id = $2 RETURNING *", [newPaymentStatus, req.params.id]);
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error, 'Failed to complete job'); }
});

app.post('/api/bookings/:id/review', protect, async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  const { rating, timeliness, thoroughness, conduct, comment, cleanerId } = req.body;
  try {
    const clientRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [authReq.user!.id]);
    const reviewerName = clientRes.rows[0]?.full_name || 'Anonymous';
    await pool.query(`INSERT INTO reviews (booking_id, cleaner_id, reviewer_name, rating, timeliness, thoroughness, conduct, comment, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`, [req.params.id, cleanerId, reviewerName, rating, timeliness, thoroughness, conduct, comment]);
    await pool.query("UPDATE bookings SET review_submitted = true WHERE id = $1", [req.params.id]);
    res.json({ message: 'Review submitted' });
  } catch (error) { handleError(res, error, 'Failed to submit review'); }
});

app.post('/api/bookings/:id/receipt', protect, async (req: Request, res: Response) => {
  const { name, dataUrl } = req.body;
  try {
    const receiptJson = JSON.stringify({ name, dataUrl });
    const result = await pool.query("UPDATE bookings SET payment_receipt = $1, payment_status = 'Pending Admin Confirmation' WHERE id = $2 RETURNING *", [receiptJson, req.params.id]);
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error, 'Failed to upload receipt'); }
});

// ============================================================================
// 8. AUTHENTICATION ROUTES (CRITICAL DEBUG ADDED)
// ============================================================================
app.post('/api/auth/register', async (req: Request, res: Response) => {
  console.log("--- REGISTER ATTEMPT ---");
  const { email, password, role, fullName, phoneNumber, state, city, address, clientType, cleanerType, companyName, experience, services, bio, chargeHourly, chargeDaily, chargePerContract, bankName, accountNumber, profilePhoto, governmentId, businessRegDoc } = req.body;
  
  try {
    // 1. Check if email exists
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (userExists.rows.length > 0) {
        console.log(`❌ Registration Failed: Email ${email} is already in the database.`);
        return res.status(400).json({ message: `User with email ${email} already exists.` });
    }
    
    // 2. Hash Password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const servicesJson = services ? JSON.stringify(services) : null; 
    
    // 3. Insert User
    const result = await pool.query(`
        INSERT INTO users (
            email, password_hash, role, full_name, phone_number, state, city, address, 
            client_type, cleaner_type, company_name, experience, services, bio, 
            charge_hourly, charge_daily, charge_per_contract, 
            bank_name, account_number, profile_photo, government_id, business_reg_doc, 
            subscription_tier, created_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, 
            $9, $10, $11, $12, $13, $14, 
            $15, $16, $17, 
            $18, $19, $20, $21, $22, 'Free', NOW()
        ) RETURNING *`, 
        [email, hashedPassword, role, fullName, phoneNumber, state, city, address, 
         clientType, cleanerType, companyName, experience, servicesJson, bio, 
         chargeHourly, chargeDaily, chargePerContract, 
         bankName, accountNumber, profilePhoto, governmentId, businessRegDoc]
    );
    
    const user = result.rows[0];
    console.log(`✅ Registration Success: User ${user.id} created.`);
    
    // Remove hash before returning
    const { password_hash, ...safeUser } = user;
    res.status(201).json({ ...safeUser, token: generateToken(user.id, role, false) });
  } catch (error: any) { 
      handleError(res, error, 'Registration failed'); 
  }
});

app.post('/api/auth/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  // CRITICAL: LOGGING DATABASE CHECK AND HASH COMPARISON
  console.log("--- LOGIN ATTEMPT ---");
  console.log(`Attempting login for email: ${email}`);
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
        console.log(`❌ Login Failed: User not found for email: ${email}`);
        return res.status(401).json({ message: 'Invalid email or password' });
    }

    // DEBUG: Log the hash from the database (DO NOT USE IN PRODUCTION)
    console.log(`DB Hash for ${email}: ${user.password_hash ? user.password_hash.substring(0, 20) + '...' : 'NONE'}`);
    
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (isMatch) {
      if (user.is_suspended) return res.status(403).json({ message: 'Account is suspended.' });
      
      const userData = { 
          id: user.id, fullName: user.full_name, email: user.email, role: user.role, 
          isAdmin: user.is_admin, adminRole: user.admin_role, profilePhoto: user.profile_photo, 
          subscriptionTier: user.subscription_tier 
      };
      console.log(`✅ Login Success: User ${user.id} logged in.`);
      res.json({ token: generateToken(user.id, user.role, user.is_admin, user.admin_role), user: userData });
    } else { 
        console.log(`❌ Login Failed: Password mismatch for user ${user.id}`);
        res.status(401).json({ message: 'Invalid email or password' }); 
    }
  } catch (error) { handleError(res, error, 'Login failed'); }
});

app.post('/api/users/subscription/upgrade', protect, async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  const { plan } = req.body;
  try {
    const result = await pool.query("UPDATE users SET pending_subscription = $1 WHERE id = $2 RETURNING *", [plan, authReq.user!.id]);
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error); }
});

app.post('/api/users/subscription/receipt', protect, async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  const { name, dataUrl } = req.body;
  try {
    const receiptJson = JSON.stringify({ name, dataUrl });
    const result = await pool.query("UPDATE users SET subscription_receipt = $1 WHERE id = $2 RETURNING *", [receiptJson, authReq.user!.id]);
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// 9. CHAT & AI ROUTES
// ============================================================================
app.post('/api/chats', protect, async (req: Request, res: Response) => {
    const authReq = req as AuthRequest;
    const { participantId } = req.body;
    try {
        const existingChat = await pool.query(`SELECT * FROM chats WHERE (participant_one = $1 AND participant_two = $2) OR (participant_one = $2 AND participant_two = $1)`, [authReq.user!.id, participantId]);
        if (existingChat.rows.length > 0) return res.json({ id: existingChat.rows[0].id, participants: [existingChat.rows[0].participant_one, existingChat.rows[0].participant_two], participantNames: {} }); 
        const result = await pool.query('INSERT INTO chats (participant_one, participant_two) VALUES ($1, $2) RETURNING *', [authReq.user!.id, participantId]);
        res.status(201).json({ id: result.rows[0].id, participants: [authReq.user!.id, participantId], participantNames: {} });
    } catch (error) { handleError(res, error, 'Failed to create chat'); }
});

app.get('/api/chats', protect, async (req: Request, res: Response) => {
    const authReq = req as AuthRequest;
    try {
        const result = await pool.query(`SELECT c.*, m.text as last_message_text, m.sender_id as last_message_sender, m.created_at as last_message_time, u1.full_name as name1, u2.full_name as name2 FROM chats c LEFT JOIN messages m ON c.last_message_id = m.id JOIN users u1 ON c.participant_one = u1.id JOIN users u2 ON c.participant_two = u2.id WHERE c.participant_one = $1 OR c.participant_two = $1 ORDER BY m.created_at DESC NULLS LAST`, [authReq.user!.id]);
        const chats = result.rows.map(row => ({ id: row.id, participants: [row.participant_one, row.participant_two], participantNames: { [row.participant_one]: row.name1, [row.participant_two]: row.name2 }, lastMessage: row.last_message_text ? { text: row.last_message_text, senderId: row.last_message_sender, timestamp: row.last_message_time } : undefined, updatedAt: row.last_message_time || row.created_at }));
        res.json(chats);
    } catch (error) { handleError(res, error); }
});

app.get('/api/chats/:id/messages', protect, async (req: Request, res: Response) => {
    try {
        const result = await pool.query('SELECT * FROM messages WHERE chat_id = $1 ORDER BY created_at ASC', [req.params.id]);
        const messages = result.rows.map(r => ({ id: r.id, chatId: r.chat_id, senderId: r.sender_id, text: r.text, timestamp: r.created_at }));
        res.json(messages);
    } catch (error) { handleError(res, error); }
});

app.post('/api/chats/:id/messages', protect, async (req: Request, res: Response) => {
    const authReq = req as AuthRequest;
    const { text } = req.body;
    try {
        const result = await pool.query('INSERT INTO messages (chat_id, sender_id, text) VALUES ($1, $2, $3) RETURNING *', [req.params.id, authReq.user!.id, text]);
        const message = result.rows[0];
        await pool.query('UPDATE chats SET last_message_id = $1, updated_at = NOW() WHERE id = $2', [message.id, req.params.id]);
        res.status(201).json({ id: message.id, chatId: message.chat_id, senderId: message.sender_id, text: message.text, timestamp: message.created_at });
    } catch (error) { handleError(res, error); }
});

app.post('/api/search/ai', async (req: Request, res: Response) => {
  const { query } = req.body;
  try {
    const response = await ai.models.generateContent({ model: 'gemini-2.5-flash', contents: `Extract key search terms (location, service type, budget) from: "${query}". Return JSON with keys: "location", "service", "maxPrice" (number).` });
    const text = response.text;
    if (!text) throw new Error("No response from AI");
    const cleanJson = text.replace(/```json|```/g, '').trim();
    const criteria = JSON.parse(cleanJson);
    let sql = "SELECT id FROM users WHERE role = 'cleaner'";
    const params: any[] = [];
    let paramIndex = 1;
    if (criteria.location) { 
        sql += ` AND (city ILIKE $${paramIndex} OR state ILIKE $${paramIndex})`; 
        params.push(`%${criteria.location}%`); 
        paramIndex++; 
    }
    // Note: AI-based service/price filtering would require more complex DB logic
    const result = await pool.query(sql, params);
    res.json({ matchingIds: result.rows.map(r => r.id) });
  } catch (error) { console.error(error); res.json({ matchingIds: [] }); }
});

app.post('/api/contact', (req: Request, res: Response) => { console.log('Contact Form:', req.body); res.json({ message: 'Message received' }); });


// ============================================================================
// 10. CRITICAL DEBUG ROUTES (FOR DEPLOYMENT ONLY)
// ============================================================================

// **DANGER: DO NOT USE ON LIVE PRODUCTION DATABASE**
app.get('/api/debug/reset-users', async (req: Request, res: Response) => {
    try {
        await pool.query('TRUNCATE users CASCADE;');
        console.log("⚠️ ALL USERS DELETED via Debug Route");
        res.send("SUCCESS: All users have been deleted. You can now register fresh.");
    } catch (e: any) {
        res.status(500).send("Error resetting users: " + e.message);
    }
});

// **DANGER: DO NOT USE ON LIVE PRODUCTION DATABASE**
app.get('/api/debug/verify-passwords', async (req: Request, res: Response) => {
    try {
        const result = await pool.query('SELECT email, password_hash FROM users LIMIT 10');
        const users = result.rows.map(u => ({ 
            email: u.email, 
            hashSnippet: u.password_hash ? u.password_hash.substring(0, 30) + '...' : 'NULL' 
        }));
        res.json({ message: 'First 10 user hashes verified.', users });
    } catch (e: any) {
        res.status(500).send("Error verifying passwords: " + e.message);
    }
});


// ============================================================================
// 11. START SERVER
// ============================================================================
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});