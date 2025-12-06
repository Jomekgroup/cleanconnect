
import { User, Cleaner, Booking, AdminRole, Chat, Message } from '../types';

// ==========================================
// CONFIGURATION
// ==========================================
// Default to localhost for development if VITE_API_URL is not set.
// If you are running the backend locally, ensure it is on port 5000.
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
// MOCK DATA (FALLBACK)
// ==========================================
const MOCK_CLEANERS: Cleaner[] = [
    {
        id: '1',
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
        cleanerType: 'Individual'
    },
    {
        id: '2',
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
        cleanerType: 'Company'
    },
    {
        id: '3',
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
        cleanerType: 'Individual'
    }
];

const MOCK_USER: User = {
    id: 'user_123',
    fullName: 'Test User',
    email: 'admin@test.com',
    phoneNumber: '08012345678',
    role: 'client',
    gender: 'Male',
    state: 'Lagos',
    city: 'Ikeja',
    address: '123 Test Street',
    isAdmin: true,
    adminRole: 'Super',
    subscriptionTier: 'Free'
};

// ==========================================
// MOCK CHAT HELPERS
// ==========================================
const CHATS_KEY = 'cleanconnect_mock_chats';
const MESSAGES_KEY = 'cleanconnect_mock_messages';

const getStoredChats = (): Chat[] => {
    try {
        return JSON.parse(localStorage.getItem(CHATS_KEY) || '[]');
    } catch { return []; }
};

const saveChats = (chats: Chat[]) => {
    localStorage.setItem(CHATS_KEY, JSON.stringify(chats));
};

const getStoredMessages = (): Message[] => {
    try {
        return JSON.parse(localStorage.getItem(MESSAGES_KEY) || '[]');
    } catch { return []; }
};

const saveMessages = (messages: Message[]) => {
    localStorage.setItem(MESSAGES_KEY, JSON.stringify(messages));
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
            console.warn("Backend login failed, using mock fallback.");
            // Mock Login Fallback
            if (email === 'admin@test.com' && password === 'password') {
                return { token: 'mock-token-admin', user: MOCK_USER };
            }
            if (email === 'client@test.com' && password === 'password') {
                return { token: 'mock-token-client', user: { ...MOCK_USER, id: 'client_1', role: 'client', isAdmin: false, fullName: 'Test Client' } };
            }
            if (email === 'cleaner@test.com' && password === 'password') {
                return { token: 'mock-token-cleaner', user: { ...MOCK_USER, id: 'cleaner_1', role: 'cleaner', isAdmin: false, fullName: 'Test Cleaner', services: ['Deep Cleaning'] } };
            }
            throw new Error("Login failed (Mock: Use admin@test.com/password)");
        }
    },

    logout: async () => {
        localStorage.removeItem('cleanconnect_token');
    },

    register: async (userData: Partial<User>): Promise<User> => {
         const payload = { ...userData };
         try {
             if (payload.profilePhoto instanceof File) payload.profilePhoto = await fileToBase64(payload.profilePhoto) as any;
             if (payload.governmentId instanceof File) payload.governmentId = await fileToBase64(payload.governmentId) as any;
             if (payload.businessRegDoc instanceof File) payload.businessRegDoc = await fileToBase64(payload.businessRegDoc) as any;

            const response = await fetch(`${API_URL}/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            return handleResponse(response);
         } catch (error) {
             console.warn("Backend register failed, returning mock success.");
             return { ...MOCK_USER, ...userData as User, id: Date.now().toString() };
         }
    },
    
    getMe: async (): Promise<User> => {
        try {
            const response = await fetch(`${API_URL}/users/me`, {
                method: 'GET',
                headers: getHeaders(),
            });
            return handleResponse(response);
        } catch (error) {
            console.warn("Backend getMe failed, returning mock session.");
            return MOCK_USER;
        }
    },

    getAllCleaners: async (): Promise<Cleaner[]> => {
        try {
            const response = await fetch(`${API_URL}/cleaners`, {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' },
            });
            return handleResponse(response);
        } catch (error) {
            console.warn("Backend unreachable. Returning mock cleaners data.");
            return MOCK_CLEANERS;
        }
    },

    getCleanerById: async (id: string) => {
        try {
            const response = await fetch(`${API_URL}/cleaners/${id}`, {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' },
            });
            return handleResponse(response);
        } catch (error) {
            return MOCK_CLEANERS.find(c => c.id === id);
        }
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
            return { matchingIds: ['1', '2'] }; // Mock results
        }
    },
    
    createBooking: async (bookingData: any): Promise<Booking> => {
        try {
            const response = await fetch(`${API_URL}/bookings`, {
                method: 'POST',
                headers: getHeaders(),
                body: JSON.stringify(bookingData),
            });
            return handleResponse(response);
        } catch (error) {
            // Return mock booking
            return {
                id: Date.now().toString(),
                ...bookingData,
                status: 'Upcoming',
                paymentStatus: bookingData.paymentMethod === 'Direct' ? 'Not Applicable' : 'Pending Payment',
                clientName: 'You',
                cleanerName: MOCK_CLEANERS.find(c => c.id === bookingData.cleanerId)?.name || 'Cleaner'
            };
        }
    },

    cancelBooking: async (bookingId: string): Promise<Booking> => {
        try {
            const response = await fetch(`${API_URL}/bookings/${bookingId}/cancel`, {
                method: 'POST',
                headers: getHeaders(),
            });
            return handleResponse(response);
        } catch (error) {
            throw new Error("Backend unreachable");
        }
    },

    markJobComplete: async (bookingId: string): Promise<Booking> => {
        try {
            const response = await fetch(`${API_URL}/bookings/${bookingId}/complete`, {
                method: 'POST',
                headers: getHeaders(),
            });
            return handleResponse(response);
        } catch (error) {
             throw new Error("Backend unreachable");
        }
    },

    submitReview: async (bookingId: string, reviewData: any) => {
        try {
            const response = await fetch(`${API_URL}/bookings/${bookingId}/review`, {
                method: 'POST',
                headers: getHeaders(),
                body: JSON.stringify(reviewData),
            });
            return handleResponse(response);
        } catch (error) {
             throw new Error("Backend unreachable");
        }
    },
    
    updateUser: async (userData: Partial<User>) => {
        const payload = { ...userData };
        try {
            if (payload.profilePhoto instanceof File) {
                payload.profilePhoto = await fileToBase64(payload.profilePhoto) as any;
            }
            const response = await fetch(`${API_URL}/users/me`, {
                method: 'PUT',
                headers: getHeaders(),
                body: JSON.stringify(payload),
            });
            return handleResponse(response);
        } catch (error) {
             return { ...MOCK_USER, ...userData as User };
        }
    },

    submitContactForm: async (formData: any) => {
        try {
            const response = await fetch(`${API_URL}/contact`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData),
            });
            return handleResponse(response);
        } catch (error) {
            return { message: "Mock success" };
        }
    },
    
    uploadReceipt: async (entityId: string, receiptData: any, type: 'booking' | 'subscription') => {
        const endpoint = type === 'booking' 
            ? `${API_URL}/bookings/${entityId}/receipt`
            : `${API_URL}/users/subscription/receipt`;

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: getHeaders(),
                body: JSON.stringify(receiptData),
            });
            return handleResponse(response);
        } catch (error) {
             return MOCK_USER; 
        }
    },

    requestSubscriptionUpgrade: async (plan: any) => {
        try {
            const response = await fetch(`${API_URL}/users/subscription/upgrade`, {
                method: 'POST',
                headers: getHeaders(),
                body: JSON.stringify({ plan: plan.name }),
            });
            return handleResponse(response);
        } catch (error) {
             return { ...MOCK_USER, pendingSubscription: plan.name };
        }
    },

    adminGetAllUsers: async (): Promise<User[]> => {
        try {
            const response = await fetch(`${API_URL}/admin/users`, {
                method: 'GET',
                headers: getHeaders(),
            });
            return handleResponse(response);
        } catch (error) {
            return [MOCK_USER, ...MOCK_CLEANERS.map(c => ({ ...c, role: 'cleaner' } as any))];
        }
    },
    
    adminUpdateUserStatus: async (userId: string, isSuspended: boolean) => {
        try {
            const response = await fetch(`${API_URL}/admin/users/${userId}/status`, {
                method: 'PATCH',
                headers: getHeaders(),
                body: JSON.stringify({ isSuspended }),
            });
            return handleResponse(response);
        } catch (error) { throw new Error("Backend unreachable"); }
    },

    adminDeleteUser: async (userId: string) => {
        try {
            const response = await fetch(`${API_URL}/admin/users/${userId}`, {
                method: 'DELETE',
                headers: getHeaders(),
            });
            return handleResponse(response);
        } catch (error) { throw new Error("Backend unreachable"); }
    },

    adminConfirmPayment: async (bookingId: string) => {
        try {
            const response = await fetch(`${API_URL}/admin/bookings/${bookingId}/confirm-payment`, {
                method: 'POST',
                headers: getHeaders(),
            });
            return handleResponse(response);
        } catch (error) { throw new Error("Backend unreachable"); }
    },

    adminApproveSubscription: async (userId: string) => {
        try {
            const response = await fetch(`${API_URL}/admin/users/${userId}/approve-subscription`, {
                method: 'POST',
                headers: getHeaders(),
            });
            return handleResponse(response);
        } catch (error) { throw new Error("Backend unreachable"); }
    },

    adminMarkAsPaid: async (bookingId: string) => {
        try {
            const response = await fetch(`${API_URL}/admin/bookings/${bookingId}/mark-paid`, {
                method: 'POST',
                headers: getHeaders(),
            });
            return handleResponse(response);
        } catch (error) { throw new Error("Backend unreachable"); }
    },

    adminCreateAdminUser: async (adminData: { email: string; fullName: string; role: AdminRole; password: string }) => {
        try {
            const response = await fetch(`${API_URL}/admin/create-admin`, {
                method: 'POST',
                headers: getHeaders(),
                body: JSON.stringify(adminData),
            });
            return handleResponse(response);
        } catch (error) { throw new Error("Backend unreachable"); }
    },

    // ==========================================
    // CHAT API
    // ==========================================
    
    createChat: async (currentUserId: string, otherUserId: string, currentUserName: string, otherUserName: string): Promise<Chat> => {
        try {
            // Attempt to create chat via Backend
            const response = await fetch(`${API_URL}/chats`, {
                method: 'POST',
                headers: getHeaders(),
                body: JSON.stringify({ participantId: otherUserId })
            });
            return handleResponse(response);
        } catch (error) {
            console.warn("Backend createChat failed, using local mock storage.");
            // Mock Fallback
            const allChats = getStoredChats();
            let chat = allChats.find(c => c.participants.includes(currentUserId) && c.participants.includes(otherUserId));

            if (!chat) {
                chat = {
                    id: Date.now().toString(),
                    participants: [currentUserId, otherUserId],
                    participantNames: {
                        [currentUserId]: currentUserName,
                        [otherUserId]: otherUserName
                    },
                    updatedAt: new Date().toISOString()
                };
                allChats.push(chat);
                saveChats(allChats);
            }
            return chat;
        }
    },

    getChats: async (userId: string): Promise<Chat[]> => {
        try {
            const response = await fetch(`${API_URL}/chats`, {
                method: 'GET',
                headers: getHeaders()
            });
            return handleResponse(response);
        } catch (error) {
             const allChats = getStoredChats();
             return allChats.filter(c => c.participants.includes(userId)).sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
        }
    },

    getChatMessages: async (chatId: string): Promise<Message[]> => {
        try {
            const response = await fetch(`${API_URL}/chats/${chatId}/messages`, {
                method: 'GET',
                headers: getHeaders()
            });
            return handleResponse(response);
        } catch (error) {
            const allMessages = getStoredMessages();
            return allMessages.filter(m => m.chatId === chatId).sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        }
    },

    sendMessage: async (chatId: string, senderId: string, text: string): Promise<Message> => {
        try {
             const response = await fetch(`${API_URL}/chats/${chatId}/messages`, {
                method: 'POST',
                headers: getHeaders(),
                body: JSON.stringify({ text })
            });
            return handleResponse(response);
        } catch (error) {
            const newMessage: Message = {
                id: Date.now().toString(),
                chatId,
                senderId,
                text,
                timestamp: new Date().toISOString()
            };

            const allMessages = getStoredMessages();
            allMessages.push(newMessage);
            saveMessages(allMessages);

            // Update chat lastMessage
            const allChats = getStoredChats();
            const chatIndex = allChats.findIndex(c => c.id === chatId);
            if (chatIndex >= 0) {
                allChats[chatIndex].lastMessage = newMessage;
                allChats[chatIndex].updatedAt = newMessage.timestamp;
                saveChats(allChats);
            }

            return newMessage;
        }
    }
};
