
import { User, Cleaner, Booking, AdminRole, Chat, Message, SupportTicket, Review } from '../types';

// ==========================================
// CONFIGURATION
// ==========================================
// Safely determine API URL. 
// We use a helper function to avoid crashing if `import.meta.env` is undefined in certain runtime environments.
const getApiUrl = () => {
    try {
        const env = (import.meta as any).env;
        if (env) {
            // In production, use relative path. In dev, use env var or localhost.
            return env.PROD 
                ? '/api' 
                : (env.VITE_API_URL || 'http://localhost:5000/api');
        }
    } catch (e) {
        // Ignore errors if import.meta is not supported
    }
    // Default fallback
    return 'http://localhost:5000/api';
};

const API_URL = getApiUrl();

// ==========================================
// MOCK DATA STORAGE & PERSISTENCE
// ==========================================
const STORAGE_PREFIX = 'cleanconnect_mock_';
const STORAGE_TIMEOUT_MS = 20 * 60 * 1000; // 20 minutes

// Helper to manage expiration
const checkStorageExpiration = () => {
    const timestamp = localStorage.getItem(`${STORAGE_PREFIX}timestamp`);
    if (!timestamp || (Date.now() - Number(timestamp) > STORAGE_TIMEOUT_MS)) {
        console.log("Mock data expired or not found. Resetting...");
        localStorage.clear(); // Clear all
        localStorage.setItem(`${STORAGE_PREFIX}timestamp`, Date.now().toString());
        initializeMockData();
    }
};

const getStoredData = <T>(key: string, defaultData: T): T => {
    try {
        const stored = localStorage.getItem(`${STORAGE_PREFIX}${key}`);
        return stored ? JSON.parse(stored) : defaultData;
    } catch {
        return defaultData;
    }
};

const setStoredData = (key: string, data: any) => {
    localStorage.setItem(`${STORAGE_PREFIX}${key}`, JSON.stringify(data));
};

// Initial Mock Data
const INITIAL_CLEANERS: Cleaner[] = [
    {
        id: 'cleaner_1',
        name: 'Sarah Jenkins',
        photoUrl: 'https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?q=80&w=200&auto=format&fit=crop',
        rating: 4.8,
        reviews: 124,
        serviceTypes: ['Residential/Domestic Cleaning', 'Deep Cleaning'],
        state: 'Lagos',
        city: 'Ikeja',
        experience: 5,
        bio: 'Professional cleaner with 5 years of experience in residential cleaning. I pay attention to details and use eco-friendly products.',
        isVerified: true,
        chargeHourly: 3500,
        subscriptionTier: 'Pro',
        cleanerType: 'Individual',
        reviewsData: [
            { reviewerName: 'John Doe', rating: 5, comment: 'Excellent service!', timeliness: 5, thoroughness: 5, conduct: 5 },
            { reviewerName: 'Jane Smith', rating: 4.6, comment: 'Very good.', timeliness: 4, thoroughness: 5, conduct: 5 }
        ]
    },
    {
        id: 'cleaner_2',
        name: 'Blue Wave Cleaning Services',
        photoUrl: 'https://images.unsplash.com/photo-1581578731117-104f2a41272c?q=80&w=200&auto=format&fit=crop',
        rating: 4.5,
        reviews: 45,
        serviceTypes: ['Commercial/Office Cleaning', 'Post-Construction'],
        state: 'Abuja',
        city: 'Garki',
        experience: 8,
        bio: 'Top-rated cleaning company serving businesses in Abuja. We specialize in office and post-construction cleaning.',
        isVerified: true,
        chargePerContract: 150000,
        chargePerContractNegotiable: true,
        subscriptionTier: 'Premium',
        cleanerType: 'Company',
        reviewsData: []
    },
    {
        id: 'cleaner_3',
        name: 'Emmanuel Okonkwo',
        photoUrl: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?q=80&w=200&auto=format&fit=crop',
        rating: 4.2,
        reviews: 28,
        serviceTypes: ['Carpet and Upholstery Cleaning', 'Laundry & ironing'],
        state: 'Lagos',
        city: 'Lekki',
        experience: 3,
        bio: 'Expert in carpet cleaning and laundry services. Prompt and reliable.',
        isVerified: false,
        chargeDaily: 12000,
        subscriptionTier: 'Standard',
        cleanerType: 'Individual',
        reviewsData: []
    }
];

const INITIAL_USERS: User[] = [
    {
        id: 'user_123',
        fullName: 'Test Client',
        email: 'client@test.com',
        phoneNumber: '08012345678',
        role: 'client',
        gender: 'Male',
        state: 'Lagos',
        city: 'Ikeja',
        address: '123 Test Street',
        isAdmin: false,
        subscriptionTier: 'Free'
    },
    {
        id: 'admin_super',
        fullName: 'Super Admin',
        email: 'super@cleanconnect.ng',
        phoneNumber: '0000000000',
        role: 'client', // Admins are technically clients with admin flags in this simple model
        isAdmin: true,
        adminRole: 'Super',
        address: 'Admin HQ',
        city: 'Abuja',
        state: 'FCT',
        gender: 'Female'
    },
    // Add cleaner users so they exist in the users table for Admin view
    ...INITIAL_CLEANERS.map(c => ({
        ...c,
        fullName: c.name,
        profilePhoto: c.photoUrl, // Map cleaner photo to user profile photo
        role: 'cleaner' as const,
        email: `cleaner_${c.id}@test.com`,
        phoneNumber: '0800000000',
        address: 'Cleaner Address',
        gender: 'Female' as const,
        isAdmin: false,
        reviewsData: c.reviewsData || []
    }))
];

const MOCK_USER: User = INITIAL_USERS[0];

const initializeMockData = () => {
    if (!localStorage.getItem(`${STORAGE_PREFIX}users`)) {
        setStoredData('users', INITIAL_USERS);
    }
    if (!localStorage.getItem(`${STORAGE_PREFIX}bookings`)) {
        setStoredData('bookings', []);
    }
};

// Run expiration check on load
checkStorageExpiration();

// Data Accessors
const getUsers = (): User[] => getStoredData('users', INITIAL_USERS);
const getBookings = (): Booking[] => getStoredData('bookings', []);
const saveUsers = (users: User[]) => setStoredData('users', users);
const saveBookings = (bookings: Booking[]) => setStoredData('bookings', bookings);


// ==========================================
// API HELPERS
// ==========================================

const getHeaders = () => {
    const token = localStorage.getItem('cleanconnect_token');
    const headers: HeadersInit = {
        'Content-Type': 'application/json',
    };
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
};

const handleResponse = async (response: Response) => {
    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `Request failed with status ${response.status}`);
    }
    if (response.status === 204) return null;
    return response.json();
};

const fileToBase64 = async (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = (event) => {
            const img = new Image();
            img.src = event.target?.result as string;
            img.onload = () => {
                const canvas = document.createElement('canvas');
                const MAX_WIDTH = 800;
                const scaleSize = MAX_WIDTH / img.width;
                const finalScale = scaleSize < 1 ? scaleSize : 1;
                canvas.width = img.width * finalScale;
                canvas.height = img.height * finalScale;
                const ctx = canvas.getContext('2d');
                if (ctx) {
                    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
                    const dataUrl = canvas.toDataURL('image/jpeg', 0.7);
                    resolve(dataUrl);
                } else {
                    reject(new Error("Failed to get canvas context"));
                }
            };
            img.onerror = (err) => reject(err);
        };
        reader.onerror = (err) => reject(err);
    });
};

// ==========================================
// API SERVICE
// ==========================================

export const apiService = {
    login: async (email: string, password?: string): Promise<{ token: string; user: User }> => {
        try {
            const response = await fetch(`${API_URL}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password }),
            });
            return handleResponse(response);
        } catch (error) {
            // For production, we want real errors. Only mock specific admin emails for demo access if DB is not set up
            if (email === 'payment@cleanconnect.ng' || email === 'verification@cleanconnect.ng' || email === 'support@cleanconnect.ng' || email === 'super@cleanconnect.ng') {
               console.warn("Using persistent mock fallback for ADMIN demo access.");
               const users = getUsers();
                // Specific Admin Checks
                if (email === 'payment@cleanconnect.ng') return { token: 'mock-token-payment', user: { ...INITIAL_USERS[1], id: 'admin_pay', fullName: 'Payment Admin', adminRole: 'Payment', email } };
                if (email === 'verification@cleanconnect.ng') return { token: 'mock-token-verif', user: { ...INITIAL_USERS[1], id: 'admin_verif', fullName: 'Verification Admin', adminRole: 'Verification', email } };
                if (email === 'support@cleanconnect.ng') return { token: 'mock-token-support', user: { ...INITIAL_USERS[1], id: 'admin_sup', fullName: 'Support Admin', adminRole: 'Support', email } };
                if (email === 'super@cleanconnect.ng') return { token: 'mock-token-super', user: { ...INITIAL_USERS[1], id: 'admin_super', fullName: 'Super Admin', adminRole: 'Super', email } };
            }
            throw error; // Rethrow real backend errors for normal users
        }
    },

    socialLogin: async (provider: 'google' | 'apple', email?: string, name?: string): Promise<{ token: string; user: User }> => {
        // Mock successful social login for demo purposes as backend OAuth is complex to set up without keys
        const emailToUse = email || `user@${provider}.com`;
        const users = getUsers();
        let user = users.find(u => u.email === emailToUse);

        if (!user) {
             user = {
                id: `social_${provider}_${Date.now()}`,
                fullName: name || `${provider === 'google' ? 'Google' : 'Apple'} User`,
                email: emailToUse,
                phoneNumber: '0000000000',
                role: 'client',
                gender: 'Other',
                state: 'Lagos',
                city: 'Ikeja',
                address: 'Social Login Address',
                subscriptionTier: 'Free',
                isAdmin: false,
                profilePhoto: emailToUse?.includes('jane') ? 'https://avatar.iran.liara.run/public/girl' : undefined
            };
            users.push(user);
            saveUsers(users);
        }
        
        return {
            token: `mock-token-${provider}`,
            user: hydrateUserWithBookings(user)
        };
    },

    logout: async () => {
        localStorage.removeItem('cleanconnect_token');
    },

    register: async (userData: Partial<User>): Promise<User> => {
         const payload = { ...userData };
         // Ensure files are base64 encoded
         if (payload.profilePhoto instanceof File) payload.profilePhoto = await fileToBase64(payload.profilePhoto) as any;
         if (payload.governmentId instanceof File) payload.governmentId = await fileToBase64(payload.governmentId) as any;
         if (payload.businessRegDoc instanceof File) payload.businessRegDoc = await fileToBase64(payload.businessRegDoc) as any;

        const response = await fetch(`${API_URL}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        return handleResponse(response);
    },
    
    getMe: async (): Promise<User> => {
        const response = await fetch(`${API_URL}/users/me`, {
            method: 'GET',
            headers: getHeaders(),
        });
        return handleResponse(response);
    },

    getAllCleaners: async (): Promise<Cleaner[]> => {
        try {
            const response = await fetch(`${API_URL}/cleaners`, {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' },
            });
            return handleResponse(response);
        } catch (error) {
            console.warn("Backend failed to fetch cleaners. Returning static list for demo purposes.");
            // Allow fallback for read-only data to prevent empty landing page if backend is sleeping
            return INITIAL_CLEANERS;
        }
    },

    getCleanerById: async (id: string) => {
        const response = await fetch(`${API_URL}/cleaners/${id}`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
        });
        return handleResponse(response);
    },

    aiSearchCleaners: async (query: string): Promise<{ matchingIds: string[] }> => {
        try {
            const response = await fetch(`${API_URL}/search/ai`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query }),
            });
            return handleResponse(response);
        } catch (error) {
            return { matchingIds: [] }; 
        }
    },
    
    createBooking: async (bookingData: any): Promise<Booking> => {
        const response = await fetch(`${API_URL}/bookings`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify(bookingData),
        });
        return handleResponse(response);
    },

    cancelBooking: async (bookingId: string): Promise<Booking> => {
        const response = await fetch(`${API_URL}/bookings/${bookingId}/cancel`, {
            method: 'POST',
            headers: getHeaders(),
        });
        return handleResponse(response);
    },

    markJobComplete: async (bookingId: string): Promise<Booking> => {
        const response = await fetch(`${API_URL}/bookings/${bookingId}/complete`, {
            method: 'POST',
            headers: getHeaders(),
        });
        return handleResponse(response);
    },

    submitReview: async (bookingId: string, reviewData: any) => {
        const response = await fetch(`${API_URL}/bookings/${bookingId}/review`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify(reviewData),
        });
        return handleResponse(response);
    },
    
    updateUser: async (userData: Partial<User>) => {
        const payload = { ...userData };
        if (payload.profilePhoto instanceof File) {
            payload.profilePhoto = await fileToBase64(payload.profilePhoto) as any;
        }
        const response = await fetch(`${API_URL}/users/me`, {
            method: 'PUT',
            headers: getHeaders(),
            body: JSON.stringify(payload),
        });
        return handleResponse(response);
    },

    submitContactForm: async (formData: any) => {
        const response = await fetch(`${API_URL}/contact`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData),
        });
        return handleResponse(response);
    },
    
    uploadReceipt: async (entityId: string, receiptData: any, type: 'booking' | 'subscription') => {
        const endpoint = type === 'booking' 
            ? `${API_URL}/bookings/${entityId}/receipt`
            : `${API_URL}/users/subscription/receipt`;

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify(receiptData),
        });
        return handleResponse(response);
    },

    requestSubscriptionUpgrade: async (plan: any) => {
        const response = await fetch(`${API_URL}/users/subscription/upgrade`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ plan: plan.name }),
        });
        return handleResponse(response);
    },

    adminGetAllUsers: async (): Promise<User[]> => {
        const response = await fetch(`${API_URL}/admin/users`, {
            method: 'GET',
            headers: getHeaders(),
        });
        return handleResponse(response);
    },
    
    adminUpdateUserStatus: async (userId: string, isSuspended: boolean) => {
        const response = await fetch(`${API_URL}/admin/users/${userId}/status`, {
            method: 'PATCH',
            headers: getHeaders(),
            body: JSON.stringify({ isSuspended }),
        });
        return handleResponse(response);
    },

    adminDeleteUser: async (userId: string) => {
        const response = await fetch(`${API_URL}/admin/users/${userId}`, {
            method: 'DELETE',
            headers: getHeaders(),
        });
        return handleResponse(response);
    },

    adminConfirmPayment: async (bookingId: string) => {
        const response = await fetch(`${API_URL}/admin/bookings/${bookingId}/confirm-payment`, {
            method: 'POST',
            headers: getHeaders(),
        });
        return handleResponse(response);
    },

    adminApproveSubscription: async (userId: string) => {
        const response = await fetch(`${API_URL}/admin/users/${userId}/approve-subscription`, {
            method: 'POST',
            headers: getHeaders(),
        });
        return handleResponse(response);
    },

    adminMarkAsPaid: async (bookingId: string) => {
        const response = await fetch(`${API_URL}/admin/bookings/${bookingId}/mark-paid`, {
            method: 'POST',
            headers: getHeaders(),
        });
        return handleResponse(response);
    },

    adminCreateAdminUser: async (adminData: { email: string; fullName: string; role: AdminRole; password: string }) => {
        const response = await fetch(`${API_URL}/admin/create-admin`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify(adminData),
        });
        return handleResponse(response);
    },

    // ==========================================
    // SUPPORT TICKET API
    // ==========================================
    createSupportTicket: async (ticketData: Partial<SupportTicket>): Promise<SupportTicket> => {
        const response = await fetch(`${API_URL}/support`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify(ticketData),
        });
        return handleResponse(response);
    },

    getUserTickets: async (): Promise<SupportTicket[]> => {
        const response = await fetch(`${API_URL}/support/my`, {
            method: 'GET',
            headers: getHeaders(),
        });
        return handleResponse(response);
    },

    getAllSupportTickets: async (): Promise<SupportTicket[]> => {
        const response = await fetch(`${API_URL}/admin/support`, {
            method: 'GET',
            headers: getHeaders(),
        });
        return handleResponse(response);
    },

    resolveSupportTicket: async (ticketId: string, adminResponse: string): Promise<SupportTicket> => {
        const response = await fetch(`${API_URL}/admin/support/${ticketId}/resolve`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ adminResponse }),
        });
        return handleResponse(response);
    },

    // ==========================================
    // CHAT API
    // ==========================================
    
    createChat: async (currentUserId: string, otherUserId: string, currentUserName: string, otherUserName: string): Promise<Chat> => {
        const response = await fetch(`${API_URL}/chats`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ participantId: otherUserId }),
        });
        return handleResponse(response);
    },

    getChats: async (userId: string): Promise<Chat[]> => {
         const response = await fetch(`${API_URL}/chats`, {
            method: 'GET',
            headers: getHeaders(),
        });
        return handleResponse(response);
    },

    getChatMessages: async (chatId: string): Promise<Message[]> => {
        const response = await fetch(`${API_URL}/chats/${chatId}/messages`, {
            method: 'GET',
            headers: getHeaders(),
        });
        return handleResponse(response);
    },

    sendMessage: async (chatId: string, senderId: string, text: string): Promise<Message> => {
        const response = await fetch(`${API_URL}/chats/${chatId}/messages`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ text }),
        });
        return handleResponse(response);
    }
};

// ==========================================
// HELPERS FOR MOCK PERSISTENCE
// ==========================================

const hydrateUserWithBookings = (user: User): User => {
    const bookings = getBookings();
    const userBookings = bookings.filter(b => b.clientId === user.id || b.cleanerId === user.id);
    return { ...user, bookingHistory: userBookings };
};
