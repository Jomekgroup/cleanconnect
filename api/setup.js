import { Pool } from 'pg';

// Direct Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

export default async function handler(req, res) {
  try {
    console.log("Starting DB Setup...");
    
    await pool.query(`
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

        -- Users Table
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

        -- Bookings Table
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

        -- Reviews Table
        CREATE TABLE IF NOT EXISTS reviews (
            id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
            booking_id UUID REFERENCES bookings(id),
            cleaner_id UUID REFERENCES users(id),
            reviewer_name TEXT, rating NUMERIC, timeliness NUMERIC, thoroughness NUMERIC, conduct NUMERIC, comment TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Chats Table
        CREATE TABLE IF NOT EXISTS chats (
            id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
            participant_one UUID REFERENCES users(id),
            participant_two UUID REFERENCES users(id),
            last_message_id UUID,
            updated_at TIMESTAMP DEFAULT NOW()
        );

        -- Messages Table
        CREATE TABLE IF NOT EXISTS messages (
            id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
            chat_id UUID REFERENCES chats(id),
            sender_id UUID REFERENCES users(id),
            text TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );
    `);

    res.status(200).send("✅ SUCCESS: Database tables have been created!");
  } catch (error) {
    console.error(error);
    res.status(500).send("❌ ERROR: " + error.message);
  }
}