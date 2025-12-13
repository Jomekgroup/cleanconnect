


import React, { useState, useMemo, useEffect } from 'react';
import { User, Booking, Receipt, AdminRole, SupportTicket } from '../types';
import { UserGroupIcon, StarIcon, XCircleIcon, EyeIcon, LifebuoyIcon } from './icons';
import { UserDetailsModal } from './UserDetailsModal';
import { AdminConfirmationModal } from './AdminConfirmationModal';
import { ReceiptViewerModal } from './ReceiptViewerModal';
import { apiService } from '../services/apiService';


interface AdminDashboardProps {
    user: User;
    allUsers: User[];
    onUpdateUser: (user: User) => void;
    onDeleteUser: (userId: string) => void;
    onMarkAsPaid: (bookingId: string) => void;
    onConfirmPayment: (bookingId: string) => void;
    onApproveSubscription: (userId: string) => void;
}

const CreateAdminModal: React.FC<{ onClose: () => void; onCreate: (data: any) => void }> = ({ onClose, onCreate }) => {
    const [fullName, setFullName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [role, setRole] = useState<AdminRole>('Support');

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        onCreate({ fullName, email, password, role });
    };

    return (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-2xl shadow-xl w-full max-w-md p-6 relative">
                 <button onClick={onClose} className="absolute top-4 right-4 text-gray-400 hover:text-gray-600">
                    <XCircleIcon className="w-6 h-6" />
                </button>
                <h3 className="text-xl font-bold text-gray-900 mb-4">Create New Admin</h3>
                <form onSubmit={handleSubmit} className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-gray-700">Full Name</label>
                        <input type="text" required value={fullName} onChange={e => setFullName(e.target.value)} className="mt-1 block w-full border border-gray-600 rounded-md shadow-sm py-2 px-3 focus:ring-primary focus:border-primary sm:text-sm bg-dark text-white placeholder-gray-400" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700">Email</label>
                        <input type="email" required value={email} onChange={e => setEmail(e.target.value)} className="mt-1 block w-full border border-gray-600 rounded-md shadow-sm py-2 px-3 focus:ring-primary focus:border-primary sm:text-sm bg-dark text-white placeholder-gray-400" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700">Password</label>
                        <input type="password" required value={password} onChange={e => setPassword(e.target.value)} className="mt-1 block w-full border border-gray-600 rounded-md shadow-sm py-2 px-3 focus:ring-primary focus:border-primary sm:text-sm bg-dark text-white placeholder-gray-400" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700">Role</label>
                        <select value={role} onChange={e => setRole(e.target.value as AdminRole)} className="mt-1 block w-full border border-gray-600 rounded-md shadow-sm py-2 px-3 focus:ring-primary focus:border-primary sm:text-sm bg-dark text-white">
                            <option value="Support">Support Admin</option>
                            <option value="Verification">Verification Admin</option>
                            <option value="Payment">Payment Admin</option>
                            <option value="Super">Super Admin</option>
                        </select>
                    </div>
                    <div className="pt-4">
                        <button type="submit" className="w-full bg-primary text-white py-2 px-4 rounded-md shadow-sm hover:bg-secondary font-medium">Create Admin</button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export const AdminDashboard: React.FC<AdminDashboardProps> = ({ user: currentUser, allUsers, onUpdateUser, onDeleteUser, onMarkAsPaid, onConfirmPayment, onApproveSubscription }) => {
    // Current user context is now passed directly as a prop, avoiding redundant fetches

    // Initial state setup to avoid flashing incorrect tabs
    const [activeTab, setActiveTab] = useState<'clients' | 'cleaners' | 'payments' | 'confirmations' | 'allBookings' | 'admins' | 'support'>('clients');
    
    const [searchTerm, setSearchTerm] = useState('');
    const [userToView, setUserToView] = useState<User | null>(null);
    const [userToSuspend, setUserToSuspend] = useState<User | null>(null);
    const [userToDelete, setUserToDelete] = useState<User | null>(null);
    const [receiptToView, setReceiptToView] = useState<Receipt | null>(null);
    const [isCreateAdminModalOpen, setIsCreateAdminModalOpen] = useState(false);
    
    // Support Tab State
    const [supportTickets, setSupportTickets] = useState<SupportTicket[]>([]);
    const [ticketToResolve, setTicketToResolve] = useState<SupportTicket | null>(null);
    const [adminResponseText, setAdminResponseText] = useState('');

    // Initial Tab Selection based on Role
    React.useEffect(() => {
         if (currentUser.adminRole === 'Payment') setActiveTab('payments');
         else if (currentUser.adminRole === 'Verification') setActiveTab('confirmations');
         else setActiveTab('clients');
    }, [currentUser.adminRole]);

    // Fetch support tickets when tab is active
    useEffect(() => {
        if (activeTab === 'support') {
            loadSupportTickets();
        }
    }, [activeTab]);

    const loadSupportTickets = async () => {
        const tickets = await apiService.getAllSupportTickets();
        setSupportTickets(tickets);
    };

    const handleResolveTicket = async () => {
        if (!ticketToResolve || !adminResponseText.trim()) return;
        try {
            await apiService.resolveSupportTicket(ticketToResolve.id, adminResponseText);
            setTicketToResolve(null);
            setAdminResponseText('');
            loadSupportTickets();
            alert("Ticket resolved successfully.");
        } catch (error) {
            alert("Failed to resolve ticket.");
        }
    };

    const handleCreateAdmin = async (data: any) => {
        try {
            const newAdmin = await apiService.adminCreateAdminUser(data);
            onUpdateUser(newAdmin); // This triggers a refresh in App.tsx which updates allUsers
            setIsCreateAdminModalOpen(false);
            alert(`Admin ${newAdmin.fullName} created successfully.`);
        } catch (error: any) {
            alert(error.message);
        }
    };

    const allBookings = useMemo(() => {
        if (!allUsers) return [];
        
        return allUsers.flatMap(u => u.bookingHistory || []).sort((a, b) => {
            const getDate = (dateStr?: string) => {
                if (!dateStr) return 0;
                // Handle DD/MM/YYYY format if present
                if (dateStr.includes('/')) {
                    const parts = dateStr.split('/');
                    if (parts.length === 3) {
                        // Create ISO format YYYY-MM-DD
                        return new Date(`${parts[2]}-${parts[1]}-${parts[0]}`).getTime();
                    }
                }
                // Handle ISO format YYYY-MM-DD or other standard formats
                const t = new Date(dateStr).getTime();
                return isNaN(t) ? 0 : t;
            };
            return getDate(b.date) - getDate(a.date);
        });
    }, [allUsers]);

    const users = useMemo(() => {
        if (!allUsers) return [];
        return allUsers.filter(user => {
            if (user.isAdmin && user.adminRole !== 'Super') return false; // Hide other admins from search unless looking at admin tab
            const term = searchTerm.toLowerCase();
            return (user.fullName || '').toLowerCase().includes(term) || (user.email || '').toLowerCase().includes(term);
        });
    }, [searchTerm, allUsers]);
    
    const clients = users.filter(u => u.role === 'client' && !u.isAdmin);
    const cleaners = users.filter(u => u.role === 'cleaner' && !u.isAdmin);
    const admins = allUsers ? allUsers.filter(u => u.isAdmin) : [];

    const [paymentFilter, setPaymentFilter] = useState<'all' | 'pending'>('all');

    const filteredPayments = useMemo(() => {
        const escrowBookings = allBookings.filter(b => b.paymentMethod === 'Escrow');
        if (paymentFilter === 'pending') {
            return escrowBookings.filter(b => b.paymentStatus === 'Pending Payout');
        }
        return escrowBookings;
    }, [allBookings, paymentFilter]);


    // Data for Confirmations tab
    const pendingPaymentConfirmations = allBookings.filter(b => b.paymentStatus === 'Pending Admin Confirmation');
    const pendingSubscriptionApprovals = allUsers ? allUsers.filter(u => u.pendingSubscription && u.subscriptionReceipt) : [];

    // Permissions Helper
    const canSeeTab = (tab: typeof activeTab) => {
        if (!currentUser?.isAdmin) return false;
        const role = currentUser.adminRole;
        
        // Fallback: If role is undefined/null but user IS admin, assume Super access (or basic) to avoid lockout
        if (!role || role === 'Super') return true;

        switch (tab) {
            case 'clients':
            case 'cleaners':
                return role === 'Support';
            case 'payments':
                return role === 'Payment';
            case 'confirmations':
                return role === 'Payment' || role === 'Verification';
            case 'allBookings':
                return role === 'Support' || role === 'Payment';
            case 'admins':
                return false; // Only Super (handled above)
            case 'support':
                return role === 'Support';
            default:
                return false;
        }
    };

    interface UserTableProps {
        users: User[];
        onView: (user: User) => void;
        onSuspend?: (user: User) => void;
        onDelete?: (user: User) => void;
        isAdminTable?: boolean;
    }

    const UserTable: React.FC<UserTableProps> = ({ users, onView, onSuspend, onDelete, isAdminTable }) => {
        const isCleanerTable = !isAdminTable && users.length > 0 && users[0]?.role === 'cleaner';
        return (
            <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                        <tr>
                            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Contact</th>
                            {!isAdminTable && <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>}
                            {isCleanerTable && <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Rating</th>}
                            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{isAdminTable ? 'Role' : 'Type'}</th>
                            <th scope="col" className="relative px-6 py-3"><span className="sr-only">Actions</span></th>
                        </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                        {users.map((user) => (
                            <tr key={user.id}>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="text-sm font-medium text-gray-900">{user.fullName}</div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="text-sm text-gray-900">{user.email}</div>
                                    <div className="text-sm text-gray-500">{user.phoneNumber}</div>
                                </td>
                                 {!isAdminTable && (
                                     <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                         <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                            user.isSuspended ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800'
                                         }`}>
                                            {user.isSuspended ? 'Suspended' : 'Active'}
                                         </span>
                                    </td>
                                )}
                                {isCleanerTable && (
                                    <td className="px-6 py-4 whitespace-nowrap">
                                        {(() => {
                                            const reviews = user.reviewsData || [];
                                            if (reviews.length === 0) {
                                                return <span className="text-sm text-gray-500">No reviews</span>;
                                            }
                                            const avgRating = reviews.reduce((acc, r) => acc + r.rating, 0) / reviews.length;
                                            return (
                                                <div className="flex items-center text-sm text-gray-900">
                                                    <StarIcon className="w-5 h-5 text-yellow-400 mr-1" />
                                                    <span className="font-semibold">{isNaN(avgRating) ? 'N/A' : avgRating.toFixed(1)}</span>
                                                    <span className="text-gray-500 ml-1">({reviews.length})</span>
                                                </div>
                                            );
                                        })()}
                                    </td>
                                )}
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                        isAdminTable 
                                            ? 'bg-purple-100 text-purple-800'
                                            : user.clientType === 'Company' || user.cleanerType === 'Company'
                                            ? 'bg-blue-100 text-blue-800'
                                            : 'bg-green-100 text-green-800'
                                    }`}>
                                        {isAdminTable ? (user.adminRole || 'Admin') : (user.clientType || user.cleanerType)}
                                    </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                    {!isAdminTable && <button onClick={() => onView(user)} className="text-primary hover:text-secondary">View</button>}
                                    {onSuspend && <button onClick={() => onSuspend(user)} className="ml-4 text-yellow-600 hover:text-yellow-900">{user.isSuspended ? 'Unsuspend' : 'Suspend'}</button>}
                                    {onDelete && <button onClick={() => onDelete(user)} className="ml-4 text-red-600 hover:text-red-900">Delete</button>}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        );
    }
    
    const PaymentTable: React.FC<{ bookings: Booking[] }> = ({ bookings }) => (
        <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                    <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Client</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Cleaner</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Amount</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Payment Status</th>
                        <th className="relative px-6 py-3"><span className="sr-only">Action</span></th>
                    </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                    {bookings.map((booking) => (
                        <tr key={booking.id}>
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{booking.clientName}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{booking.cleanerName}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">₦{(booking.totalAmount || booking.amount).toLocaleString()}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{booking.date}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{booking.paymentStatus}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                {booking.paymentStatus === 'Pending Payout' && (
                                    <button onClick={() => onMarkAsPaid(booking.id)} className="bg-primary text-white px-3 py-1 rounded-md text-xs font-semibold hover:bg-secondary">Mark as Paid</button>
                                )}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
             {bookings.length === 0 && <p className="text-center text-gray-500 p-4">No records found.</p>}
        </div>
    );

    const ConfirmationPaymentTable: React.FC<{ bookings: Booking[]}> = ({ bookings }) => (
         <div>
            <h3 className="text-xl font-semibold p-4">Payment Confirmations (Escrow)</h3>
            <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                        <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Client</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Cleaner</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Amount</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Receipt</th>
                            <th className="relative px-6 py-3"><span className="sr-only">Action</span></th>
                        </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                        {bookings.map((booking) => (
                            <tr key={booking.id}>
                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{booking.clientName}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{booking.cleanerName}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">₦{(booking.totalAmount || booking.amount).toLocaleString()}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{booking.date}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {booking.paymentReceipt ? (
                                        <button 
                                            onClick={() => setReceiptToView(booking.paymentReceipt!)} 
                                            className="text-primary hover:text-secondary flex items-center gap-1 font-medium"
                                        >
                                            <EyeIcon className="w-4 h-4" />
                                            View Receipt
                                        </button>
                                    ) : (
                                        <span className="text-gray-400 italic">No receipt</span>
                                    )}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                    <button onClick={() => onConfirmPayment(booking.id)} className="bg-primary text-white px-3 py-1 rounded-md text-xs font-semibold hover:bg-secondary">Confirm Payment</button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
                 {bookings.length === 0 && <p className="text-center text-gray-500 p-4">No records found.</p>}
            </div>
        </div>
    );
    
    const getJobStatusBadge = (status: Booking['status']) => {
        switch(status) {
            case 'Upcoming': return 'bg-indigo-100 text-indigo-800';
            case 'Completed': return 'bg-green-100 text-green-800';
            case 'Cancelled': return 'bg-red-100 text-red-800';
            default: return 'bg-gray-100 text-gray-800';
        }
    }
    const getPaymentStatusBadge = (status: Booking['paymentStatus']) => {
        switch(status) {
            case 'Pending Payment': return 'bg-yellow-100 text-yellow-800';
            case 'Pending Admin Confirmation': return 'bg-blue-100 text-blue-800';
            case 'Confirmed': return 'bg-teal-100 text-teal-800';
            case 'Paid': return 'bg-green-100 text-green-800';
            case 'Pending Payout': return 'bg-purple-100 text-purple-800';
            case 'Not Applicable': return 'bg-gray-100 text-gray-800';
            default: return 'bg-gray-100 text-gray-800';
        }
    }

    const SubscriptionTable: React.FC<{ users: User[], onApprove: (userId: string) => void }> = ({ users, onApprove }) => (
        <div>
            <h3 className="text-xl font-semibold p-4">Subscription Approvals</h3>
            <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                        <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Cleaner Name</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Requested Plan</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Receipt</th>
                            <th className="relative px-6 py-3"><span className="sr-only">Action</span></th>
                        </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                        {users.map((user) => (
                            <tr key={user.id}>
                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{user.fullName}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{user.pendingSubscription}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {user.subscriptionReceipt ? (
                                        <button 
                                            onClick={() => setReceiptToView(user.subscriptionReceipt!)} 
                                            className="text-primary hover:text-secondary flex items-center gap-1 font-medium"
                                        >
                                            <EyeIcon className="w-4 h-4" />
                                            View Receipt
                                        </button>
                                    ) : (
                                        <span className="text-gray-400 italic">No receipt</span>
                                    )}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                    <button onClick={() => onApprove(user.id)} className="bg-primary text-white px-3 py-1 rounded-md text-xs font-semibold hover:bg-secondary">Approve Upgrade</button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
                {users.length === 0 && <p className="text-center text-gray-500 p-4">No pending approvals.</p>}
            </div>
        </div>
    );
    
    // Only render dashboard if we have current user context (passed via prop now)
    if (!currentUser) return <div className="p-8 text-center">Loading admin dashboard...</div>;

    const canSeeClients = canSeeTab('clients');
    const canSeeCleaners = canSeeTab('cleaners');
    const canSeePayments = canSeeTab('payments');
    const canSeeConfirmations = canSeeTab('confirmations');
    const canSeeAllBookings = canSeeTab('allBookings');
    const canSeeAdmins = canSeeTab('admins');
    const canSeeSupport = canSeeTab('support');

    return (
        <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-12">
            <div className="flex flex-col sm:flex-row justify-between items-center mb-8">
                 <h1 className="text-3xl font-bold text-dark flex items-center gap-3">
                    <UserGroupIcon className="w-8 h-8"/>
                    <span>{currentUser.adminRole || 'System'} Admin Dashboard</span>
                </h1>
                <div className="mt-4 sm:mt-0 w-full sm:w-auto">
                    <input 
                        type="text"
                        placeholder="Search by name or email..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full sm:w-64 px-4 py-2 border border-gray-600 rounded-lg focus:ring-primary focus:border-primary bg-dark text-white placeholder-gray-400"
                    />
                </div>
            </div>

             <div className="border-b border-gray-200 overflow-x-auto">
                <nav className="-mb-px flex space-x-8" aria-label="Tabs">
                    {canSeeClients && (
                        <button
                            onClick={() => setActiveTab('clients')}
                            className={`${
                                activeTab === 'clients'
                                ? 'border-primary text-primary'
                                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                            } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}
                        >
                            Manage Clients ({clients.length})
                        </button>
                    )}
                    {canSeeCleaners && (
                        <button
                            onClick={() => setActiveTab('cleaners')}
                            className={`${
                                activeTab === 'cleaners'
                                ? 'border-primary text-primary'
                                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                            } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}
                        >
                            Manage Cleaners ({cleaners.length})
                        </button>
                    )}
                    {canSeePayments && (
                        <button
                            onClick={() => setActiveTab('payments')}
                            className={`${
                                activeTab === 'payments'
                                ? 'border-primary text-primary'
                                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                            } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}
                        >
                            Payments
                        </button>
                    )}
                    {canSeeConfirmations && (
                         <button
                            onClick={() => setActiveTab('confirmations')}
                            className={`${
                                activeTab === 'confirmations'
                                ? 'border-primary text-primary'
                                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                            } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}
                        >
                            Confirmations
                        </button>
                    )}
                    {canSeeAllBookings && (
                        <button
                            onClick={() => setActiveTab('allBookings')}
                            className={`${
                                activeTab === 'allBookings'
                                ? 'border-primary text-primary'
                                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                            } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}
                        >
                        All Bookings ({allBookings.length})
                        </button>
                    )}
                    {canSeeAdmins && (
                        <button
                            onClick={() => setActiveTab('admins')}
                            className={`${
                                activeTab === 'admins'
                                ? 'border-primary text-primary'
                                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                            } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}
                        >
                            Manage Admins ({admins.length})
                        </button>
                    )}
                    {canSeeSupport && (
                        <button
                            onClick={() => setActiveTab('support')}
                            className={`${
                                activeTab === 'support'
                                ? 'border-primary text-primary'
                                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                            } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-1`}
                        >
                            <LifebuoyIcon className="w-4 h-4" />
                            Support Tickets
                        </button>
                    )}
                </nav>
            </div>
            
            <div className="mt-8 bg-white shadow-md rounded-lg">
                {activeTab === 'clients' && canSeeClients && <UserTable users={clients} onView={setUserToView} onSuspend={setUserToSuspend} onDelete={setUserToDelete} />}
                {activeTab === 'cleaners' && canSeeCleaners && <UserTable users={cleaners} onView={setUserToView} onSuspend={setUserToSuspend} onDelete={setUserToDelete} />}
                {activeTab === 'payments' && canSeePayments && (
                    <div>
                        <div className="p-4 flex items-center justify-between">
                             <h3 className="text-xl font-semibold">Payment History (Escrow)</h3>
                             <div className="flex items-center gap-2 rounded-lg bg-gray-100 p-1">
                                <button onClick={() => setPaymentFilter('all')} className={`px-3 py-1 text-sm font-medium rounded-md ${paymentFilter === 'all' ? 'bg-white shadow' : 'text-gray-600'}`}>All</button>
                                <button onClick={() => setPaymentFilter('pending')} className={`px-3 py-1 text-sm font-medium rounded-md ${paymentFilter === 'pending' ? 'bg-white shadow' : 'text-gray-600'}`}>Pending Payout</button>
                             </div>
                        </div>
                        <PaymentTable bookings={filteredPayments} />
                    </div>
                )}
                 {activeTab === 'confirmations' && canSeeConfirmations && (
                    <div>
                        {/* Only show Payment confirmations to Super or Payment Admins */}
                        {(currentUser.adminRole === 'Super' || currentUser.adminRole === 'Payment' || !currentUser.adminRole) && (
                            <ConfirmationPaymentTable bookings={pendingPaymentConfirmations} />
                        )}
                        
                        {(currentUser.adminRole === 'Super' || !currentUser.adminRole) && (
                             <div className="border-t mt-4"></div>
                        )}

                        {/* Only show Subscription confirmations to Super or Verification Admins */}
                        {(currentUser.adminRole === 'Super' || currentUser.adminRole === 'Verification' || !currentUser.adminRole) && (
                            <div className="mt-4">
                                <SubscriptionTable users={pendingSubscriptionApprovals} onApprove={onApproveSubscription} />
                            </div>
                        )}
                    </div>
                )}
                 {activeTab === 'allBookings' && canSeeAllBookings && (
                     <div>
                        <h3 className="text-xl font-semibold p-4">All Bookings History</h3>
                        <div className="overflow-x-auto">
                           <table className="min-w-full divide-y divide-gray-200">
                                <thead className="bg-gray-50">
                                    <tr>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Client</th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Cleaner</th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Service</th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Amount</th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Payment</th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                    </tr>
                                </thead>
                                <tbody className="bg-white divide-y divide-gray-200">
                                    {allBookings.map(b => (
                                        <tr key={b.id}>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{b.clientName}</td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{b.cleanerName}</td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{b.service}</td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{b.date}</td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">₦{(b.amount || 0).toLocaleString()}</td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                <div className="flex flex-col gap-1 items-start">
                                                     <span className="text-xs">{b.paymentMethod}</span>
                                                     <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${getPaymentStatusBadge(b.paymentStatus)}`}>
                                                        {b.paymentStatus}
                                                     </span>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                 <span className={`text-xs font-bold px-2 py-1 rounded-full ${getJobStatusBadge(b.status)}`}>
                                                    {b.status}
                                                 </span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                           </table>
                        </div>
                     </div>
                )}
                {activeTab === 'admins' && canSeeAdmins && (
                    <div>
                        <div className="p-4 flex justify-between items-center">
                            <h3 className="text-xl font-semibold">Manage Administrators</h3>
                            <button 
                                onClick={() => setIsCreateAdminModalOpen(true)}
                                className="bg-primary text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-secondary transition-colors"
                            >
                                + Create New Admin
                            </button>
                        </div>
                        <UserTable users={admins} onView={() => {}} onSuspend={setUserToSuspend} onDelete={setUserToDelete} isAdminTable={true} />
                    </div>
                )}

                {activeTab === 'support' && canSeeSupport && (
                    <div className="p-4">
                        <h3 className="text-xl font-semibold mb-4">Support Tickets</h3>
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            <div className="space-y-4">
                                {supportTickets.map(ticket => (
                                    <div 
                                        key={ticket.id} 
                                        onClick={() => setTicketToResolve(ticket)}
                                        className={`p-4 border rounded-lg cursor-pointer hover:bg-gray-50 transition-colors ${ticketToResolve?.id === ticket.id ? 'border-primary ring-1 ring-primary bg-gray-50' : 'border-gray-200'}`}
                                    >
                                        <div className="flex justify-between items-start">
                                            <h4 className="font-bold text-gray-900">{ticket.subject}</h4>
                                            <span className={`px-2 py-0.5 text-xs font-bold rounded-full ${ticket.status === 'Resolved' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}`}>
                                                {ticket.status}
                                            </span>
                                        </div>
                                        <p className="text-sm text-gray-500 mt-1">{ticket.userName} ({ticket.userRole}) • {ticket.category}</p>
                                        <p className="text-xs text-gray-400 mt-1">{new Date(ticket.createdAt).toLocaleString()}</p>
                                    </div>
                                ))}
                                {supportTickets.length === 0 && <p className="text-gray-500">No support tickets found.</p>}
                            </div>

                            {ticketToResolve ? (
                                <div className="bg-white border rounded-lg p-6 shadow-sm sticky top-4 h-fit">
                                    <div className="flex justify-between items-start mb-4">
                                        <h3 className="text-lg font-bold">{ticketToResolve.subject}</h3>
                                        <button onClick={() => setTicketToResolve(null)} className="text-gray-400 hover:text-gray-600">
                                            <XCircleIcon className="w-5 h-5"/>
                                        </button>
                                    </div>
                                    
                                    <div className="bg-gray-50 p-3 rounded mb-4 text-sm">
                                        <p className="font-semibold text-gray-700 mb-1">User Message:</p>
                                        <p className="text-gray-600 whitespace-pre-wrap">{ticketToResolve.message}</p>
                                    </div>

                                    {ticketToResolve.status === 'Resolved' ? (
                                        <div className="bg-green-50 p-3 rounded text-sm">
                                            <p className="font-semibold text-green-800 mb-1">Response:</p>
                                            <p className="text-green-700">{ticketToResolve.adminResponse}</p>
                                        </div>
                                    ) : (
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-2">Reply & Resolve</label>
                                            <textarea
                                                rows={5}
                                                className="w-full border rounded-md p-2 text-sm mb-4 focus:ring-primary focus:border-primary"
                                                placeholder="Write your response to the user..."
                                                value={adminResponseText}
                                                onChange={(e) => setAdminResponseText(e.target.value)}
                                            ></textarea>
                                            <button 
                                                onClick={handleResolveTicket}
                                                className="w-full bg-primary text-white py-2 rounded-lg font-semibold hover:bg-secondary"
                                            >
                                                Send Response & Resolve Ticket
                                            </button>
                                        </div>
                                    )}
                                </div>
                            ) : (
                                <div className="hidden lg:flex items-center justify-center border border-dashed rounded-lg bg-gray-50 text-gray-400 min-h-[300px]">
                                    Select a ticket to view details
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
            
            {userToView && <UserDetailsModal user={userToView} onClose={() => setUserToView(null)} />}

            {userToSuspend && (
                <AdminConfirmationModal
                    title={userToSuspend.isSuspended ? 'Unsuspend User' : 'Suspend User'}
                    message={`Are you sure you want to ${userToSuspend.isSuspended ? 'unsuspend' : 'suspend'} ${userToSuspend.fullName}? ${userToSuspend.isSuspended ? '' : 'They will not be able to log in.'}`}
                    confirmText={userToSuspend.isSuspended ? 'Unsuspend' : 'Suspend'}
                    onConfirm={() => {
                        onUpdateUser({ ...userToSuspend, isSuspended: !userToSuspend.isSuspended });
                        setUserToSuspend(null);
                    }}
                    onClose={() => setUserToSuspend(null)}
                    confirmButtonClass="bg-yellow-600 hover:bg-yellow-500 focus-visible:outline-yellow-600"
                />
            )}

            {userToDelete && (
                <AdminConfirmationModal
                    title="Delete User"
                    message={`Are you sure you want to permanently delete ${userToDelete.fullName}? This action cannot be undone.`}
                    confirmText="Delete"
                    onConfirm={() => {
                        onDeleteUser(userToDelete.id);
                        setUserToDelete(null);
                    }}
                    onClose={() => setUserToDelete(null)}
                    confirmButtonClass="bg-red-600 hover:bg-red-500 focus-visible:outline-red-600"
                />
            )}
            
            {receiptToView && <ReceiptViewerModal receipt={receiptToView} onClose={() => setReceiptToView(null)} />}
            
            {isCreateAdminModalOpen && (
                <CreateAdminModal onClose={() => setIsCreateAdminModalOpen(false)} onCreate={handleCreateAdmin} />
            )}

        </div>
    );
};
