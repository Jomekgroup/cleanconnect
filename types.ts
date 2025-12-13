
export interface Review {
  reviewerName: string;
  rating: number; // This will be the average
  timeliness?: number;
  thoroughness?: number;
  conduct?: number;
  comment: string;
}

export interface Cleaner {
  id: string; // FIX: Changed from number to string to match UUID
  name: string;
  photoUrl: string;
  rating: number;
  reviews: number;
  serviceTypes: string[];
  state: string;
  city: string;
  otherCity?: string;
  experience: number;
  bio: string;
  isVerified: boolean;
  chargeHourly?: number;
  chargeDaily?: number;
  chargePerContract?: number;
  chargePerContractNegotiable?: boolean;
  subscriptionTier: 'Free' | 'Standard' | 'Pro' | 'Premium';
  accountNumber?: string;
  bankName?: string;
  phoneNumber?: string;
  cleanerType?: 'Individual' | 'Company';
  reviewsData?: Review[];
}

export type UserRole = 'client' | 'cleaner';

// New: Specific Admin Roles
export type AdminRole = 'Super' | 'Support' | 'Verification' | 'Payment';

export interface Receipt {
  name: string;
  dataUrl: string;
}

export interface Booking {
  id: string;
  service: string;
  date: string;
  amount: number; // This is the cleaner's charge
  totalAmount?: number; // This is amount + escrow fee
  status: 'Upcoming' | 'Completed' | 'Cancelled';
  clientName: string;
  cleanerName: string;
  clientId: string;
  cleanerId: string; // FIX: Changed from number to string to match UUID
  reviewSubmitted?: boolean;
  paymentMethod: 'Escrow' | 'Direct';
  paymentStatus: 'Pending Payment' | 'Pending Admin Confirmation' | 'Confirmed' | 'Pending Payout' | 'Paid' | 'Not Applicable';
  paymentReceipt?: Receipt; 
  jobApprovedByClient?: boolean;
}

export interface User {
  id: string;
  email: string;
  password?: string;
  phoneNumber: string;
  role: UserRole;
  fullName: string;
  gender: 'Male' | 'Female' | 'Other';
  state: string;
  city: string;
  otherCity?: string;
  address: string;
  selfie?: File | string;
  governmentId?: File | string;
  clientType?: 'Individual' | 'Company';
  companyName?: string;
  companyAddress?: string;
  bookingHistory?: Booking[];
  isAdmin?: boolean;
  adminRole?: AdminRole; // New field to distinguish admin types
  isSuspended?: boolean;
  // Cleaner-specific
  cleanerType?: 'Individual' | 'Company';
  experience?: number;
  services?: string[];
  bio?: string;
  profilePhoto?: File | string;
  nin?: string;
  businessRegDoc?: File | string;
  chargeHourly?: number;
  chargeDaily?: number;
  chargePerContract?: number;
  chargePerContractNegotiable?: boolean;
  accountNumber?: string;
  bankName?: string;
  subscriptionTier?: 'Free' | 'Standard' | 'Pro' | 'Premium';
  pendingSubscription?: 'Free' | 'Standard' | 'Pro' | 'Premium'; // The plan they've requested to upgrade to
  subscriptionReceipt?: Receipt;
  subscriptionEndDate?: string; // e.g., '2025-07-31'
  reviewsData?: Review[];
  // New fields for usage tracking
  monthlyNewClientsIds?: string[]; // Array of unique client IDs for the month
  monthlyUsageResetDate?: string; // e.g., '2024-08-01'
}

export interface SubscriptionPlan {
    name: 'Free' | 'Standard' | 'Pro' | 'Premium';
    priceMonthly: number;
    priceYearly: number;
    features: string[];
    isRecommended?: boolean;
}

export type View = 
  | 'landing' 
  | 'auth'
  | 'signup' 
  | 'clientDashboard' 
  | 'cleanerDashboard' 
  | 'cleanerProfile'
  | 'adminDashboard'
  | 'subscription'
  | 'profile'
  | 'about'
  | 'servicesPage'
  | 'help'
  | 'contact'
  | 'terms'
  | 'privacy'
  | 'searchResults';