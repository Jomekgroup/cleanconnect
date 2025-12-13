
import React, { useState, useEffect, Suspense } from 'react';
import { Header } from './components/Header';
import { Footer } from './components/Footer';
import { BookingModal } from './components/BookingModal';
import { EscrowPaymentDetailsModal } from './components/EscrowPaymentDetailsModal';
import { SubscriptionPaymentDetailsModal } from './components/SubscriptionPaymentDetailsModal';
import { StarIcon } from './components/icons';
import { ErrorBoundary } from './components/ErrorBoundary';

import { User, Cleaner, View, SubscriptionPlan, Review, Receipt } from './types';
import { apiService } from './services/apiService';

// Lazy Load Pages to optimize initial bundle size
const LandingPage = React.lazy(() => import('./components/LandingPage').then(module => ({ default: module.LandingPage })));
const Auth = React.lazy(() => import('./components/Auth').then(module => ({ default: module.Auth })));
const SignupForm = React.lazy(() => import('./components/SignupForm').then(module => ({ default: module.SignupForm })));
const Dashboard = React.lazy(() => import('./components/Dashboard').then(module => ({ default: module.Dashboard })));
const AdminDashboard = React.lazy(() => import('./components/AdminDashboard').then(module => ({ default: module.AdminDashboard })));
const SubscriptionPage = React.lazy(() => import('./components/SubscriptionPage').then(module => ({ default: module.SubscriptionPage })));
const ClientDashboard = React.lazy(() => import('./components/ClientDashboard').then(module => ({ default: module.ClientDashboard })));
const AboutPage = React.lazy(() => import('./components/AboutPage').then(module => ({ default: module.AboutPage })));
const ServicesPage = React.lazy(() => import('./components/ServicesPage').then(module => ({ default: module.ServicesPage })));
const HelpCenterPage = React.lazy(() => import('./components/HelpCenterPage').then(module => ({ default: module.HelpCenterPage })));
const ContactPage = React.lazy(() => import('./components/ContactPage').then(module => ({ default: module.ContactPage })));
const TermsPage = React.lazy(() => import('./components/TermsPage').then(module => ({ default: module.TermsPage })));
const PrivacyPage = React.lazy(() => import('./components/PrivacyPage').then(module => ({ default: module.PrivacyPage })));
const SearchResultsPage = React.lazy(() => import('./components/SearchResultsPage').then(module => ({ default: module.SearchResultsPage })));


interface CleanerProfileProps {
    cleaner: Cleaner;
    onNavigate: (v: View) => void;
    onBook: (cleaner: Cleaner) => void;
}

const CleanerProfile: React.FC<CleanerProfileProps> = ({ cleaner, onNavigate, onBook }) => {
    return (
        <div className="p-8 container mx-auto">
        <button onClick={() => onNavigate('searchResults')} className="text-primary mb-4 font-semibold hover:underline flex items-center gap-1">
            <span>&larr;</span> Back to Results
        </button>
        <div className="bg-white p-6 rounded-lg shadow-lg">
            <img src={cleaner.photoUrl} alt={cleaner.name} className="w-32 h-32 rounded-full mx-auto object-cover mb-4 ring-4 ring-primary/20" />
            <h2 className="text-3xl font-bold text-center">{cleaner.name}</h2>
            <div className="flex items-center justify-center mt-2 space-x-2 text-gray-700">
                <StarIcon className="w-5 h-5 text-yellow-400" />
                <span className="font-bold text-lg">{cleaner.rating.toFixed(1)}</span>
                <span className="text-gray-500">({cleaner.reviews} reviews)</span>
            </div>
            <p className="mt-4 max-w-2xl mx-auto text-center">{cleaner.bio}</p>
             <div className="flex justify-center mt-8">
                <button 
                    onClick={() => onBook(cleaner)}
                    className="w-full max-w-xs bg-primary text-white p-3 rounded-lg font-bold hover:bg-secondary"
                >
                    Book this Cleaner
                </button>
            </div>
        </div>
    </div>
    )
};

interface SearchFilters {
    service: string;
    location: string;
    minPrice: string;
    maxPrice: string;
    minRating: string;
}

const LoadingSpinner = () => (
    <div className="flex justify-center items-center h-[calc(100vh-200px)]">
        <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-primary"></div>
    </div>
);

const App: React.FC = () => {
    const [view, setView] = useState<View>('landing');
    const [user, setUser] = useState<User | null>(null);
    const [allUsers, setAllUsers] = useState<User[]>([]);
    const [allCleaners, setAllCleaners] = useState<Cleaner[]>([]);
    const [selectedCleaner, setSelectedCleaner] = useState<Cleaner | null>(null);
    
    const [signupEmail, setSignupEmail] = useState<string | null>(null);
    const [signupPassword, setSignupPassword] = useState<string | null>(null);
    
    const [initialAuthTab, setInitialAuthTab] = useState<'login' | 'signup'>('login');
    const [initialFilters, setInitialFilters] = useState<SearchFilters | null>(null);
    const [authMessage, setAuthMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null);

    const [isLoading, setIsLoading] = useState(true);
    const [appError, setAppError] = useState<string | null>(null);

    // Modal states
    const [cleanerToBook, setCleanerToBook] = useState<Cleaner | null>(null);
    const [isBookingModalOpen, setIsBookingModalOpen] = useState(false);
    const [isEscrowModalOpen, setIsEscrowModalOpen] = useState(false);
    const [bookingDetailsForEscrow, setBookingDetailsForEscrow] = useState<{ cleaner: Cleaner; totalAmount: number } | null>(null);
    const [isSubPaymentModalOpen, setIsSubPaymentModalOpen] = useState(false);
    const [planToUpgrade, setPlanToUpgrade] = useState<SubscriptionPlan | null>(null);
    
    // State to remember booking intention for logged-out users
    const [cleanerToRememberForBooking, setCleanerToRememberForBooking] = useState<Cleaner | null>(null);

    // Refetches all app data. Used after state-changing actions.
    const refetchAllData = async (currentUser: User) => {
        try {
            const [cleaners, users] = await Promise.all([
                apiService.getAllCleaners(),
                currentUser.isAdmin ? apiService.adminGetAllUsers() : Promise.resolve([])
            ]);
            setAllCleaners(cleaners);
            setAllUsers(users);
        } catch (error: any) {
            setAppError("Failed to refresh application data: " + error.message);
        }
    };


    // On initial app load, check for an existing session token
    useEffect(() => {
        const checkSession = async () => {
            setIsLoading(true);
            setAppError(null);
            
            // Always fetch cleaners first so landing page works
            try {
                const cleaners = await apiService.getAllCleaners();
                setAllCleaners(cleaners);
            } catch (error: any) {
                console.error("Failed to fetch cleaners:", error);
                if (error.message.includes('Failed to fetch')) {
                    setAppError("Could not connect to the backend server. Please ensure the server is running and accessible.");
                } else {
                    setAppError("An error occurred while fetching cleaners.");
                }
            }

            const token = localStorage.getItem('cleanconnect_token');
            if (token) {
                try {
                    const currentUser = await apiService.getMe();
                    await handleAuthSuccess(currentUser, false); // Don't navigate on session load, stay on current or default
                } catch (error) {
                    console.error("Session expired or invalid.", error);
                    handleLogout();
                }
            }
            
            setIsLoading(false);
        };
        checkSession();
    }, []);

    const handleNavigate = (targetView: View) => {
        setView(targetView);
        window.scrollTo(0, 0);
    };

    const handleNavigateToAuth = (tab: 'login' | 'signup') => {
        setInitialAuthTab(tab);
        setView('auth');
    };
    
    const handleLoginAttempt = async (email: string, password?: string) => {
        setAuthMessage(null);
        try {
            const { token, user: loggedInUser } = await apiService.login(email, password);
            localStorage.setItem('cleanconnect_token', token);
            await handleAuthSuccess(loggedInUser);
        } catch (error: any) {
            setAuthMessage({ type: 'error', text: error.message || 'Login failed. Please try again.' });
        }
    };

    const handleAuthSuccess = async (userData: User, shouldNavigate = true) => {
        setUser(userData);
        await refetchAllData(userData);

        if (cleanerToRememberForBooking) {
            handleStartBookingProcess(cleanerToRememberForBooking);
            setCleanerToRememberForBooking(null);
            return;
        }
        
        if (shouldNavigate) {
            if (userData.isAdmin) {
                handleNavigate('adminDashboard');
            } else {
                handleNavigate(userData.role === 'client' ? 'clientDashboard' : 'cleanerDashboard');
            }
        }
    };
    
    const handleInitialSignup = (email: string, password: string) => {
        setAuthMessage(null);
        setSignupEmail(email);
        setSignupPassword(password);
        setView('signup');
    };
    
    const handleSignupComplete = async (newUser: User) => {
        if (!signupPassword) {
            alert("An error occurred during signup. Password was not provided.");
            handleNavigateToAuth('signup');
            return;
        }
        const newUserWithPassword: User = { ...newUser, password: signupPassword };
        try {
            await apiService.register(newUserWithPassword);
            setAuthMessage({ type: 'success', text: "Account created! Please log in." });
            handleNavigateToAuth('login');
        } catch (error: any) {
            alert(error.message || "Signup failed. A user with this email may already exist.");
            handleNavigateToAuth('login');
        }
    };

    const handleLogout = () => {
        apiService.logout();
        setUser(null);
        setAllUsers([]);
        localStorage.removeItem('cleanconnect_token');
        setCleanerToRememberForBooking(null);
        handleNavigate('landing');
    };
    
    const handleSelectCleaner = (cleaner: Cleaner) => {
        setSelectedCleaner(cleaner);
        handleNavigate('cleanerProfile');
    };

    const handleSearchFromHero = (filters: SearchFilters) => {
        setInitialFilters(filters);
        if (user) {
            handleNavigate('clientDashboard');
        } else {
            handleNavigate('searchResults');
        }
    };

    const handleUpdateUser = async (updatedData: User) => {
        try {
            const updatedUser = await apiService.updateUser(updatedData);
            setUser(updatedUser);
            if (updatedUser.isAdmin) {
                await refetchAllData(updatedUser);
            }
            alert("Profile updated successfully!");
        } catch(error: any) {
            alert(`Failed to update profile: ${error.message}`);
        }
    };

    const handleConfirmBooking = async (paymentMethod: 'Direct' | 'Escrow', cleaner: Cleaner) => {
         if (!user) return;
        try {
            const baseAmount = cleaner.chargeHourly || cleaner.chargeDaily || cleaner.chargePerContract || 5000;
            const bookingData = {
                cleanerId: cleaner.id,
                service: cleaner.serviceTypes[0] || 'General Cleaning',
                date: new Date().toISOString().split('T')[0],
                amount: baseAmount,
                totalAmount: paymentMethod === 'Escrow' ? baseAmount * 1.1 : baseAmount,
                paymentMethod,
            };
            const newBooking = await apiService.createBooking(bookingData);
            
            setUser(prev => prev ? ({...prev, bookingHistory: [...(prev.bookingHistory || []), newBooking] }) : null);

            handleCloseBookingModals();
            alert(`Booking created! ${paymentMethod === 'Escrow' ? 'Please upload your payment receipt from your dashboard.' : ''}`);
            handleNavigate('clientDashboard');
        } catch (error: any) {
            alert(`Booking failed: ${error.message}`);
        }
    };
    
    const handleCancelBooking = async (bookingId: string) => {
        try {
            const cancelledBooking = await apiService.cancelBooking(bookingId);
            setUser(prev => prev ? ({...prev, bookingHistory: prev.bookingHistory?.map(b => b.id === bookingId ? cancelledBooking : b)}) : null);
            alert("Booking cancelled successfully.");
        } catch(e: any) { alert(`Cancellation failed: ${e.message}`); }
    };

    const handleApproveJobCompletion = async (bookingId: string) => {
        try {
            const completedBooking = await apiService.markJobComplete(bookingId);
            setUser(prev => prev ? ({...prev, bookingHistory: prev.bookingHistory?.map(b => b.id === bookingId ? completedBooking : b)}) : null);
        } catch(e: any) { alert(`Failed to mark as complete: ${e.message}`); }
    };

    const handleReviewSubmit = async (bookingId: string, cleanerId: string, reviewData: Omit<Review, 'reviewerName'>) => {
        try {
            await apiService.submitReview(bookingId, {...reviewData, cleanerId});
            setUser(prev => prev ? ({...prev, bookingHistory: prev.bookingHistory?.map(b => b.id === bookingId ? {...b, reviewSubmitted: true} : b)}) : null);
            alert("Review submitted successfully!");
        } catch(e: any) { alert(`Failed to submit review: ${e.message}`); }
    };
    
    // Admin Actions
    const handleDeleteUser = async (userId: string) => {
        try {
            await apiService.adminDeleteUser(userId);
            setAllUsers(prev => prev.filter(u => u.id !== userId));
            alert("User deleted successfully.");
        } catch(e: any) { alert(`Failed to delete user: ${e.message}`); }
    };
    
    const handleStartBookingProcess = (cleaner: Cleaner) => {
        if (!user) {
            setCleanerToRememberForBooking(cleaner);
            setAuthMessage({ type: 'error', text: 'Please sign up or log in to book this cleaner.' });
            handleNavigateToAuth('signup');
            return;
        }
        setCleanerToBook(cleaner);
        setIsBookingModalOpen(true);
    };

    const handleCloseBookingModals = () => {
        setIsBookingModalOpen(false);
        setIsEscrowModalOpen(false);
        setCleanerToBook(null);
        setBookingDetailsForEscrow(null);
    };

    const handleProceedToEscrow = (bookingData: { cleaner: Cleaner; totalAmount: number; }) => {
        setBookingDetailsForEscrow(bookingData);
        setIsBookingModalOpen(false);
        setIsEscrowModalOpen(true);
    };
    
    const handleUpgradeRequest = (plan: SubscriptionPlan) => { setIsSubPaymentModalOpen(true); setPlanToUpgrade(plan); };
    
    const handleConfirmSubscriptionRequest = async (plan: SubscriptionPlan) => {
        try {
            const updatedUser = await apiService.requestSubscriptionUpgrade(plan);
            setUser(updatedUser);
            handleCloseBookingModals();
            alert("Upgrade request sent. Please upload your payment receipt from your dashboard to finalize.");
            handleNavigate('cleanerDashboard');
        } catch (error: any) {
            alert(`Failed to request upgrade: ${error.message}`);
        }
    };
    
    const handleUploadBookingReceipt = async (bookingId: string, receipt: Receipt) => {
        try {
            const updatedUser = await apiService.uploadReceipt(bookingId, receipt, 'booking');
            setUser(updatedUser);
            alert('Receipt uploaded successfully. Admin will confirm your payment shortly.');
        } catch (error: any) {
            alert(`Failed to upload receipt: ${error.message}`);
        }
    };
    
    const handleUploadSubscriptionReceipt = async (receipt: Receipt) => {
        if (!user) return;
        try {
            const updatedUser = await apiService.uploadReceipt(user.id, receipt, 'subscription');
            setUser(updatedUser);
            alert('Subscription receipt uploaded successfully. Your plan will be upgraded upon admin confirmation.');
        } catch (error: any) {
            alert(`Failed to upload receipt: ${error.message}`);
        }
    };
    
    const handleMarkAsPaid = async (bookingId: string) => {
        if (!user) return;
        try {
            await apiService.adminMarkAsPaid(bookingId);
            await refetchAllData(user);
            alert("Booking marked as paid successfully.");
        } catch (e: any) {
            alert(`Failed to mark as paid: ${e.message}`);
        }
    };

    const handleConfirmEscrowPayment = async (bookingId: string) => {
        if (!user) return;
        try {
            await apiService.adminConfirmPayment(bookingId);
            await refetchAllData(user);
            alert("Payment confirmed successfully.");
        } catch (e: any) {
            alert(`Failed to confirm payment: ${e.message}`);
        }
    };

    const handleApproveSubscription = async (userId: string) => {
        if (!user) return;
        try {
            await apiService.adminApproveSubscription(userId);
            await refetchAllData(user);
            alert("Subscription approved successfully.");
        } catch (e: any) {
            alert(`Failed to approve subscription: ${e.message}`);
        }
    };


    const renderContent = () => {
        if (isLoading) {
            return <LoadingSpinner />;
        }

        switch (view) {
            case 'auth':
                return <Auth 
                    initialTab={initialAuthTab}
                    onNavigate={handleNavigate} 
                    onLoginAttempt={handleLoginAttempt}
                    onInitialSignup={handleInitialSignup}
                    authMessage={authMessage}
                    onAuthMessageDismiss={() => setAuthMessage(null)}
                />;
            case 'signup':
                if (signupEmail) {
                    return <SignupForm email={signupEmail} onComplete={handleSignupComplete} onNavigate={handleNavigate}/>;
                }
                handleNavigate('auth');
                return null;
            case 'clientDashboard':
                if (user && user.role === 'client') {
                    return <ClientDashboard 
                                user={user} 
                                allCleaners={allCleaners}
                                onSelectCleaner={handleSelectCleaner}
                                initialFilters={initialFilters}
                                clearInitialFilters={() => setInitialFilters(null)}
                                onNavigate={handleNavigate}
                                onCancelBooking={handleCancelBooking}
                                onReviewSubmit={handleReviewSubmit}
                                onApproveJobCompletion={handleApproveJobCompletion}
                                onUploadBookingReceipt={handleUploadBookingReceipt}
                                appError={appError}
                           />;
                }
                handleNavigate('auth');
                return null;
            case 'cleanerDashboard':
                if (user && user.role === 'cleaner') {
                    return <Dashboard user={user} onUpdateUser={handleUpdateUser} onNavigate={handleNavigate} onUploadSubscriptionReceipt={handleUploadSubscriptionReceipt} />;
                }
                handleNavigate('auth');
                return null;
            case 'adminDashboard':
                if (user && user.isAdmin) {
                    return <AdminDashboard 
                                allUsers={allUsers}
                                onUpdateUser={handleUpdateUser}
                                onDeleteUser={handleDeleteUser}
                                onMarkAsPaid={handleMarkAsPaid}
                                onConfirmPayment={handleConfirmEscrowPayment}
                                onApproveSubscription={handleApproveSubscription}
                           />;
                }
                handleNavigate('auth');
                return null;
            case 'cleanerProfile':
                if (selectedCleaner) {
                    return <CleanerProfile cleaner={selectedCleaner} onNavigate={handleNavigate} onBook={handleStartBookingProcess} />;
                }
                handleNavigate('landing');
                return null;
            case 'subscription':
                if (user && user.role === 'cleaner') {
                    return <SubscriptionPage 
                                currentPlan={user.subscriptionTier || 'Free'} 
                                onSelectPlan={handleUpgradeRequest} 
                           />;
                }
                 handleNavigate('cleanerDashboard');
                return null;
             case 'searchResults':
                return <SearchResultsPage
                    allCleaners={allCleaners}
                    onSelectCleaner={handleSelectCleaner}
                    initialFilters={initialFilters}
                    clearInitialFilters={() => setInitialFilters(null)}
                    appError={appError}
                />;
            case 'about': return <AboutPage />;
            case 'servicesPage': return <ServicesPage />;
            case 'help': return <HelpCenterPage />;
            case 'contact': return <ContactPage />;
            case 'terms': return <TermsPage />;
            case 'privacy': return <PrivacyPage />;
            case 'landing':
            default:
                return <LandingPage 
                    cleaners={allCleaners}
                    onNavigate={handleNavigate} 
                    onSelectCleaner={handleSelectCleaner}
                    onSearch={handleSearchFromHero}
                    appError={appError}
                />;
        }
    };

    return (
        <div className="min-h-screen flex flex-col font-sans bg-light">
            <ErrorBoundary>
                <Header user={user} onNavigate={handleNavigate} onLogout={handleLogout} onNavigateToAuth={handleNavigateToAuth} />
                <main className="flex-grow">
                    <Suspense fallback={<LoadingSpinner />}>
                        {renderContent()}
                    </Suspense>
                </main>
                <Footer onNavigate={handleNavigate} />
                
                 {isBookingModalOpen && cleanerToBook && user && (
                    <BookingModal
                        cleaner={cleanerToBook}
                        user={user}
                        onClose={handleCloseBookingModals}
                        onConfirmBooking={handleConfirmBooking}
                        onProceedToEscrow={handleProceedToEscrow}
                    />
                )}
                {isEscrowModalOpen && bookingDetailsForEscrow && (
                    <EscrowPaymentDetailsModal
                        cleaner={bookingDetailsForEscrow.cleaner}
                        totalAmount={bookingDetailsForEscrow.totalAmount}
                        onClose={handleCloseBookingModals}
                        onConfirmBooking={handleConfirmBooking}
                    />
                )}
                {isSubPaymentModalOpen && planToUpgrade && (
                    <SubscriptionPaymentDetailsModal
                        plan={planToUpgrade}
                        onClose={() => {
                            setIsSubPaymentModalOpen(false);
                            setPlanToUpgrade(null);
                        }}
                        onConfirm={handleConfirmSubscriptionRequest}
                    />
                )}
            </ErrorBoundary>
        </div>
    );
};

export default App;
