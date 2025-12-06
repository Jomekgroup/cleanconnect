import { User, Cleaner, Booking, AdminRole, Chat, Message } from '../types';

// ==========================================
// CONFIGURATION
// ==========================================
// This ensures we look for the Vercel variable, or default to localhost
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
// API SERVICE (STRICT MODE - NO AUTH MOCKS)
// ==========================================

export const apiService = {
    // 1. LOGIN - Removed Try/Catch to force real errors
    login: async (email: string, password?: string): Promise<{ token: string; user: User }> => {
        const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });
        return handleResponse(response);
    },

    logout: async () => {
        localStorage.removeItem('cleanconnect_token');
    },

    // 2. REGISTER - Removed Mock Fallback
    register: async (userData: Partial<User>): Promise<User> => {
         const payload = { ...userData };
         
         // Convert files if they exist
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
    
    // 3. GET ME - Removed Mock Fallback
    getMe: async (): Promise<User> => {
        const response = await fetch(`${API_URL}/users/me`, {
            method: 'GET',
            headers: getHeaders(),
        });
        return handleResponse(response);
    },

    // Keep Mocks for Cleaners only if DB is empty, but try fetch first
    getAllCleaners: async (): Promise<Cleaner[]> => {
        try {
            const response = await fetch(`${API_URL}/cleaners`, {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' },
            });
            return handleResponse(response);
        } catch (error) {
            console.warn("Backend unreachable. Returning empty list for now.");
            return []; 
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

    // Chat methods simplified for now (fetching from backend primarily)
    createChat: async (currentUserId: string, otherUserId: string, currentUserName: string, otherUserName: string): Promise<Chat> => {
        const response = await fetch(`${API_URL}/chats`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ participantId: otherUserId })
        });
        return handleResponse(response);
    },

    getChats: async (userId: string): Promise<Chat[]> => {
        const response = await fetch(`${API_URL}/chats`, {
            method: 'GET',
            headers: getHeaders()
        });
        return handleResponse(response);
    },

    getChatMessages: async (chatId: string): Promise<Message[]> => {
        const response = await fetch(`${API_URL}/chats/${chatId}/messages`, {
            method: 'GET',
            headers: getHeaders()
        });
        return handleResponse(response);
    },

    sendMessage: async (chatId: string, senderId: string, text: string): Promise<Message> => {
        const response = await fetch(`${API_URL}/chats/${chatId}/messages`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ text })
        });
        return handleResponse(response);
    }
};