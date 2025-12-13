import { User, Cleaner, Booking, AdminRole } from '../types';

// ==========================================
// CONFIGURATION
// ==========================================
// This points to your backend URL. In production, this env var will be set.
// In development, it defaults to localhost.
// We use optional chaining and casting to handle environments where import.meta.env might be undefined.
const API_URL = (import.meta as any).env?.VITE_API_URL || 'http://localhost:5000/api';

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
    // Handle empty responses (like 204 No Content)
    if (response.status === 204) return null;
    return response.json();
};

// Helper to convert File to Compressed Base64
// We keep this client-side to easily send images as JSON strings to the backend.
const fileToBase64 = async (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = (event) => {
            const img = new Image();
            img.src = event.target?.result as string;
            img.onload = () => {
                const canvas = document.createElement('canvas');
                // Limit max dimensions to save bandwidth (800px width max)
                const MAX_WIDTH = 800;
                const scaleSize = MAX_WIDTH / img.width;
                const finalScale = scaleSize < 1 ? scaleSize : 1;
                
                canvas.width = img.width * finalScale;
                canvas.height = img.height * finalScale;
                
                const ctx = canvas.getContext('2d');
                if (ctx) {
                    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
                    // Compress to JPEG with 0.7 quality
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
// API SERVICE (HTTP CLIENT)
// ==========================================

export const apiService = {
    // ===================================
    // AUTHENTICATION
    // ===================================
    login: async (email: string, password?: string): Promise<{ token: string; user: User }> => {
        const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });
        return handleResponse(response);
    },

    logout: async () => {
        // Ideally call backend to invalidate token if using blacklisting
        // For JWT, mostly client-side removal
        localStorage.removeItem('cleanconnect_token');
    },

    register: async (userData: Partial<User>): Promise<User> => {
         // Process Files to Base64 before sending over JSON
         const payload = { ...userData };
         
         if (payload.profilePhoto instanceof File) {
             payload.profilePhoto = await fileToBase64(payload.profilePhoto) as any;
         }
         if (payload.governmentId instanceof File) {
             payload.governmentId = await fileToBase64(payload.governmentId) as any;
         }
         if (payload.businessRegDoc instanceof File) {
             payload.businessRegDoc = await fileToBase64(payload.businessRegDoc) as any;
         }

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

    // ===================================
    // PUBLIC DATA
    // ===================================
    getAllCleaners: async (): Promise<Cleaner[]> => {
        const response = await fetch(`${API_URL}/cleaners`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }, // Public endpoint
        });
        return handleResponse(response);
    },

    getCleanerById: async (id: string) => {
        const response = await fetch(`${API_URL}/cleaners/${id}`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
        });
        return handleResponse(response);
    },

    aiSearchCleaners: async (query: string): Promise<{ matchingIds: string[] }> => {
        const response = await fetch(`${API_URL}/search/ai`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query }),
        });
        return handleResponse(response);
    },
    
    // ===================================
    // USER ACTIONS
    // ===================================
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
            method: 'POST', // or PATCH/PUT depending on backend design
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
        // entityId is either bookingId or userId depending on type
        const endpoint = type === 'booking' 
            ? `${API_URL}/bookings/${entityId}/receipt`
            : `${API_URL}/users/subscription/receipt`;

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify(receiptData), // { name: string, dataUrl: string }
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

    // ===================================
    // ADMIN ACTIONS
    // ===================================
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
    }
};