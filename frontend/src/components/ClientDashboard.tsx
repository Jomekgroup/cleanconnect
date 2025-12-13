
import React, { useState, useEffect, useMemo, useRef } from 'react';
import { Cleaner, User, View, Booking, Review, Receipt } from '../types';
import { SparklesIcon, MapPinIcon, BriefcaseIcon, ChevronDownIcon, StarIcon, CreditCardIcon, UserGroupIcon, ChatBubbleLeftRightIcon, LifebuoyIcon, PencilIcon, UserIcon } from './icons';
import { CleanerCard } from './CleanerCard';
import { getAiRecommendedServices } from '../services/geminiService';
import { CLEANING_SERVICES } from '../constants/services';
import { CancellationConfirmationModal } from './CancellationConfirmationModal';
import { ReviewModal } from './ReviewModal';
import { apiService } from '../services/apiService';
import { ChatInterface } from './ChatInterface';
import { SupportTicketSection } from './SupportTicketSection';
import { NIGERIA_LOCATIONS } from '../constants/locations';

interface ServiceRecommendationsProps {
    isLoading: boolean;
    recommendations: string[];
    onSelect: (service: string) => void;
}

const ServiceRecommendations: React.FC<ServiceRecommendationsProps> = ({ isLoading, recommendations, onSelect }) => {
    if (isLoading) {
        return (
            <div className="mt-8">
                 <div className="bg-gray-200 h-8 w-1/3 rounded-md animate-pulse mb-4"></div>
                 <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                     {Array.from({ length: 4 }).map((_, index) => (
                        <div key={index} className="bg-gray-200 h-24 rounded-lg animate-pulse"></div>
                     ))}
                 </div>
            </div>
        );
    }

    if (recommendations.length === 0) {
        return null; // Don't show anything if there are no recommendations
    }

    return (
        <div className="mt-8">
            <h3 className="text-2xl font-bold flex items-center gap-2 text-dark">
                <SparklesIcon className="w-6 h-6 text-primary"/>
                <span>Recommended For You</span>
            </h3>
            <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-4">
                {recommendations.map(service => (
                    <button 
                        key={service}
                        onClick={() => onSelect(service)}
                        className="p-4 bg-white rounded-lg shadow-md text-left hover:shadow-lg hover:-translate-y-1 transition-all duration-300 border border-transparent hover:border-primary"
                    >
                        <p className="font-semibold text-dark">{service}</p>
                        <span className="text-sm text-primary font-medium mt-2 inline-block">Find Cleaners &rarr;</span>
                    </button>
                ))}
            </div>
        </div>
    );
};

const ProfileField: React.FC<{ label: string; value?: string | number | null | string[]; isEditing?: boolean; children?: React.ReactNode }> = ({ label, value, isEditing, children }) => (
    <div className="py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:py-5 border-b border-gray-100 last:border-0">
        <dt className="text-sm font-medium text-gray-500">{label}</dt>
        <dd className="mt-1 flex text-sm text-gray-900 sm:col-span-2 sm:mt-0">
            {isEditing ? children : (
                <div className="flex-grow">
                    {Array.isArray(value) ? (
                        <div className="flex flex-wrap gap-2">
                            {value.length > 0 ? value.map(item => (
                                <span key={item} className="bg-green-100 text-primary text-xs font-semibold px-2.5 py-1 rounded-full">{item}</span>
                            )) : 'N/A'}
                        </div>
                    ) : (value || 'N/A')}
                </div>
            )}
        </dd>
    </div>
);

interface ClientDashboardProps {
    user: User;
    allCleaners: Cleaner[]; 
    onSelectCleaner: (cleaner: Cleaner) => void;
    initialFilters?: { service: string, location: string, minPrice: string, maxPrice: string, minRating: string } | null;
    clearInitialFilters: () => void;
    onNavigate: (view: View) => void;
    onCancelBooking: (bookingId: string) => void;
    onReviewSubmit: (bookingId: string, cleanerId: string, reviewData: Omit<Review, 'reviewerName'>) => void;
    onApproveJobCompletion: (bookingId: string) => void;
    onUploadBookingReceipt: (bookingId: string, receipt: Receipt) => void;
    onUpdateUser: (user: User) => void;
    appError: string | null;
    initialTab?: 'find' | 'bookings' | 'messages' | 'support' | 'profile';
}

export const ClientDashboard: React.FC<ClientDashboardProps> = ({ user, allCleaners, onSelectCleaner, initialFilters, clearInitialFilters, onNavigate, onCancelBooking, onReviewSubmit, onApproveJobCompletion, onUploadBookingReceipt, onUpdateUser, appError, initialTab }) => {
    const [recommendations, setRecommendations] = useState<string[]>([]);
    const [isRecsLoading, setIsRecsLoading] = useState(true);
    const [activeTab, setActiveTab] = useState<'find' | 'bookings' | 'messages' | 'support' | 'profile'>(initialTab || 'find');
    const [bookingToCancel, setBookingToCancel] = useState<Booking | null>(null);
    const [bookingToReview, setBookingToReview] = useState<Booking | null>(null);
    const [activeFilters, setActiveFilters] = useState({ service: '', location: '', minPrice: '', maxPrice: '', minRating: '' });
    const [isAdvancedOpen, setIsAdvancedOpen] = useState(false);

    // Profile Editing State
    const [isEditingProfile, setIsEditingProfile] = useState(false);
    const [profileFormData, setProfileFormData] = useState<any>(user);
    const [profilePhotoPreview, setProfilePhotoPreview] = useState<string | null>(null);
    const [cities, setCities] = useState<string[]>([]);

    const fileInputRef = useRef<HTMLInputElement>(null);
    const [bookingIdForUpload, setBookingIdForUpload] = useState<string | null>(null);
    
    useEffect(() => {
        if (initialFilters) {
            setActiveFilters(initialFilters);
            if (initialFilters.minPrice || initialFilters.maxPrice || initialFilters.minRating) {
                setIsAdvancedOpen(true);
            }
            clearInitialFilters();
            setActiveTab('find');
        }
    }, [initialFilters, clearInitialFilters]);

    useEffect(() => {
        if (initialTab) {
            setActiveTab(initialTab);
        }
    }, [initialTab]);

    useEffect(() => {
        setIsRecsLoading(true);
        setRecommendations(getAiRecommendedServices(user));
        setIsRecsLoading(false);
        setProfileFormData(user);
        
        if (user.profilePhoto && user.profilePhoto instanceof File) {
            setProfilePhotoPreview(URL.createObjectURL(user.profilePhoto));
        } else if (typeof user.profilePhoto === 'string') {
             setProfilePhotoPreview(user.profilePhoto);
        }
    }, [user]);

    // Update cities when state changes in profile form
    useEffect(() => {
        if (profileFormData.state) {
            const selectedState = NIGERIA_LOCATIONS.find(s => s.name === profileFormData.state);
            setCities(selectedState ? [...selectedState.towns, 'Other'] : ['Other']);
        } else {
            setCities([]);
        }
    }, [profileFormData.state]);

    const displayedCleaners = useMemo(() => {
        if (appError) return [];
        const { service, location, minPrice, maxPrice, minRating } = activeFilters;
        return allCleaners.filter(cleaner => {
            const serviceMatch = service ? cleaner.serviceTypes.includes(service) : true;
            const locationMatch = location 
                ? cleaner.city.toLowerCase().includes(location.toLowerCase()) || 
                  cleaner.state.toLowerCase().includes(location.toLowerCase()) ||
                  (cleaner.otherCity && cleaner.otherCity.toLowerCase().includes(location.toLowerCase()))
                : true;
            let priceMatch = true;
            if (minPrice || maxPrice) {
                const min = Number(minPrice) || 0;
                const max = Number(maxPrice) || Infinity;
                const rates = [cleaner.chargeHourly, cleaner.chargeDaily, cleaner.chargePerContract].filter(r => r !== undefined && r !== null) as number[];
                if (rates.length > 0) {
                     priceMatch = rates.some(r => r >= min && r <= max);
                } else {
                    priceMatch = false; 
                }
            }
            let ratingMatch = true;
            if (minRating) {
                ratingMatch = cleaner.rating >= Number(minRating);
            }
            return serviceMatch && locationMatch && priceMatch && ratingMatch;
        });
    }, [activeFilters, allCleaners, appError]);

    const resultsTitle = useMemo(() => {
        if (activeFilters.service || activeFilters.location || activeFilters.minPrice || activeFilters.maxPrice || activeFilters.minRating) return 'Filtered Results';
        return 'All Available Cleaners';
    }, [activeFilters]);

    const handleFilterChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
        const { name, value } = e.target;
        setActiveFilters(prev => ({ ...prev, [name]: value }));
    };
    
    const handleRecommendationSelect = (service: string) => {
        setActiveFilters(prev => ({ ...prev, service }));
        setActiveTab('find');
        window.scrollTo(0, 0);
    };

    const handleReceiptUploadClick = (bookingId: string) => {
        setBookingIdForUpload(bookingId);
        fileInputRef.current?.click();
    };

    const handleFileSelected = (event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.files && event.target.files[0] && bookingIdForUpload) {
            const file = event.target.files[0];
            const reader = new FileReader();
            reader.onloadend = () => {
                if (reader.result) {
                    onUploadBookingReceipt(bookingIdForUpload, { name: file.name, dataUrl: reader.result as string });
                }
            };
            reader.readAsDataURL(file);
            setBookingIdForUpload(null);
        }
        if(event.target) {
            event.target.value = '';
        }
    };

    const handleMessageCleaner = async (cleanerId: string, cleanerName: string) => {
        try {
            await apiService.createChat(user.id, cleanerId, user.fullName, cleanerName);
            setActiveTab('messages');
        } catch (error) {
            alert('Could not start chat. Please try again.');
        }
    };

    // Profile Handlers
    const handleProfileInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
        const { name, value } = e.target;
        setProfileFormData((prev: any) => {
            const updates: any = { ...prev, [name]: value };
            // If state changes, reset city
            if (name === 'state') {
                updates.city = '';
                updates.otherCity = '';
            }
            return updates;
        });
    };

    const handleProfileFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            const file = e.target.files[0];
            setProfileFormData((prev: any) => ({...prev, profilePhoto: file }));
            setProfilePhotoPreview(URL.createObjectURL(file));
        }
    };

    const handleSaveProfile = () => {
        onUpdateUser(profileFormData);
        setIsEditingProfile(false);
    };

    const handleCancelProfile = () => {
        setProfileFormData(user);
        setIsEditingProfile(false);
    };

    const renderValueOrInput = (name: keyof User, type: 'text' | 'email' | 'tel' | 'number' = 'text', options: Record<string, any> = {}) => {
        return (
            <input
                type={type}
                name={name}
                id={name}
                value={profileFormData[name] as string || ''}
                onChange={handleProfileInputChange}
                className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm"
                {...options}
            />
        );
    };

     const getPaymentStatusBadgeClass = (status: Booking['paymentStatus']) => {
        switch (status) {
            case 'Pending Payment': return 'bg-yellow-100 text-yellow-800';
            case 'Pending Admin Confirmation': return 'bg-blue-100 text-blue-800';
            case 'Confirmed': return 'bg-teal-100 text-teal-800';
            case 'Paid': return 'bg-green-100 text-green-800';
            case 'Pending Payout': return 'bg-purple-100 text-purple-800';
            case 'Not Applicable': default: return 'bg-gray-200 text-gray-800';
        }
    };

    // Determine the display name (Company Name if applicable, else First Name)
    const displayName = user.clientType === 'Company' && user.companyName 
        ? user.companyName 
        : user.fullName.split(' ')[0];

    // Determine the name to display in profile header
    const profileDisplayName = profileFormData.clientType === 'Company' && profileFormData.companyName 
        ? profileFormData.companyName 
        : profileFormData.fullName;

    return (
        <div className="p-4 sm:p-8 container mx-auto">
             <input type="file" ref={fileInputRef} onChange={handleFileSelected} className="hidden" accept="image/*,.pdf" />
             <div className="flex flex-col sm:flex-row justify-between items-center mb-6 gap-4">
                <h1 className="text-3xl font-bold text-dark text-center sm:text-left">Welcome back, {displayName}!</h1>
            </div>

            <div className="border-b border-gray-200 mb-6 overflow-x-auto">
                <nav className="-mb-px flex space-x-8" aria-label="Tabs">
                    <button onClick={() => setActiveTab('find')} className={`${activeTab === 'find' ? 'border-primary text-primary' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'} whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}>
                        Find a Cleaner
                    </button>
                    <button onClick={() => setActiveTab('bookings')} className={`${activeTab === 'bookings' ? 'border-primary text-primary' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'} whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}>
                        My Bookings
                    </button>
                    <button onClick={() => setActiveTab('messages')} className={`${activeTab === 'messages' ? 'border-primary text-primary' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'} whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2`}>
                        <ChatBubbleLeftRightIcon className="w-4 h-4" />
                        Messages
                    </button>
                    <button onClick={() => setActiveTab('support')} className={`${activeTab === 'support' ? 'border-primary text-primary' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'} whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2`}>
                        <LifebuoyIcon className="w-4 h-4" />
                        Support
                    </button>
                    <button onClick={() => setActiveTab('profile')} className={`${activeTab === 'profile' ? 'border-primary text-primary' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'} whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2`}>
                        <UserIcon className="w-4 h-4" />
                        My Profile
                    </button>
                </nav>
            </div>
            
            {activeTab === 'find' && (
                <div>
                     <div className="bg-white p-6 rounded-lg shadow-md">
                        <h2 className="text-lg font-bold mb-4">Search Cleaners</h2>
                        <form className="space-y-4" onSubmit={(e) => e.preventDefault()}>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-center">
                                <div className="md:col-span-1">
                                    <label htmlFor="service" className="text-xs font-semibold text-gray-500 ml-2 block text-left">Service</label>
                                    <div className="relative mt-1">
                                        <BriefcaseIcon className="w-5 h-5 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
                                        <select 
                                            id="service" 
                                            name="service"
                                            className="w-full pl-10 pr-8 p-3 bg-dark border border-gray-600 rounded-lg appearance-none text-light focus:outline-none focus:ring-2 focus:ring-primary"
                                            value={activeFilters.service}
                                            onChange={handleFilterChange}
                                        >
                                            <option value="">All Services</option>
                                            {CLEANING_SERVICES.map((serviceName) => (
                                                <option key={serviceName} value={serviceName}>{serviceName}</option>
                                            ))}
                                        </select>
                                        <ChevronDownIcon className="w-5 h-5 text-gray-400 absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                                    </div>
                                </div>
                                <div className="md:col-span-1">
                                    <label htmlFor="location" className="text-xs font-semibold text-gray-500 ml-2 block text-left">Location</label>
                                    <div className="relative mt-1">
                                        <MapPinIcon className="w-5 h-5 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
                                        <input 
                                            type="text" 
                                            id="location" 
                                            name="location"
                                            placeholder="e.g., Ikeja, Lagos" 
                                            className="w-full pl-10 p-3 bg-dark border-gray-600 rounded-lg text-light placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary"
                                            value={activeFilters.location}
                                            onChange={handleFilterChange}
                                        />
                                    </div>
                                </div>
                            </div>
                            
                            <div className={`overflow-hidden transition-all duration-300 ease-in-out ${isAdvancedOpen ? 'max-h-96 opacity-100' : 'max-h-0 opacity-0'}`}>
                                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 pt-4 border-t border-gray-200">
                                    <div>
                                        <label className="text-xs font-semibold text-gray-500 ml-2 block text-left">Min Price (₦)</label>
                                        <div className="relative mt-1">
                                            <CreditCardIcon className="w-5 h-5 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
                                            <input 
                                                type="number" 
                                                name="minPrice"
                                                placeholder="Min" 
                                                className="w-full pl-10 p-3 bg-dark border-gray-600 rounded-lg text-light placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary"
                                                value={activeFilters.minPrice}
                                                onChange={handleFilterChange}
                                                min="0"
                                            />
                                        </div>
                                    </div>
                                    <div>
                                        <label className="text-xs font-semibold text-gray-500 ml-2 block text-left">Max Price (₦)</label>
                                        <div className="relative mt-1">
                                            <CreditCardIcon className="w-5 h-5 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
                                            <input 
                                                type="number" 
                                                name="maxPrice"
                                                placeholder="Max" 
                                                className="w-full pl-10 p-3 bg-dark border-gray-600 rounded-lg text-light placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary"
                                                value={activeFilters.maxPrice}
                                                onChange={handleFilterChange}
                                                min="0"
                                            />
                                        </div>
                                    </div>
                                    <div>
                                        <label className="text-xs font-semibold text-gray-500 ml-2 block text-left">Min Rating</label>
                                        <div className="relative mt-1">
                                            <StarIcon className="w-5 h-5 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
                                            <select 
                                                name="minRating"
                                                className="w-full pl-10 pr-8 p-3 bg-dark border border-gray-600 rounded-lg appearance-none text-light focus:outline-none focus:ring-2 focus:ring-primary"
                                                value={activeFilters.minRating}
                                                onChange={handleFilterChange}
                                            >
                                                <option value="">Any Rating</option>
                                                <option value="4.5">4.5 & up</option>
                                                <option value="4.0">4.0 & up</option>
                                                <option value="3.0">3.0 & up</option>
                                            </select>
                                            <ChevronDownIcon className="w-5 h-5 text-gray-400 absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div className="flex justify-start">
                                <button
                                    type="button"
                                    onClick={() => setIsAdvancedOpen(!isAdvancedOpen)}
                                    className="text-sm font-medium text-gray-600 hover:text-primary flex items-center gap-1"
                                >
                                    {isAdvancedOpen ? 'Hide' : 'Show'} Advanced Filters
                                    <ChevronDownIcon className={`w-4 h-4 transform transition-transform ${isAdvancedOpen ? 'rotate-180' : ''}`} />
                                </button>
                            </div>
                        </form>
                     </div>

                      {(displayedCleaners.length === 0 && !activeFilters.service && !activeFilters.location) && (
                         <ServiceRecommendations isLoading={isRecsLoading} recommendations={recommendations} onSelect={handleRecommendationSelect} />
                    )}

                    <div className="mt-8">
                        <h3 className="text-2xl font-bold">{resultsTitle}</h3>
                        {appError && (
                            <div className="mt-4 bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg relative text-center" role="alert">
                                <strong className="font-bold">Connection Error! </strong>
                                <span className="block sm:inline">{appError}</span>
                            </div>
                        )}
                        {displayedCleaners.length > 0 && !appError ? (
                            <div className="mt-4 grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
                                {displayedCleaners.map(cleaner => (<CleanerCard key={cleaner.id} cleaner={cleaner} onClick={() => onSelectCleaner(cleaner)} />))}
                            </div>
                        ) : !appError ? (
                            <p className="mt-4 text-gray-500 bg-white p-6 rounded-lg shadow-sm">No cleaners found matching your criteria.</p>
                        ) : null }
                    </div>
                </div>
            )}
            
            {activeTab === 'bookings' && (
                <div className="bg-white p-6 rounded-lg shadow-md">
                    <h2 className="text-2xl font-bold text-dark mb-4">My Booking History</h2>
                     {user.bookingHistory && user.bookingHistory.length > 0 ? (
                        <ul className="space-y-4">
                            {user.bookingHistory.map((item) => {
                                const cleaner = allCleaners.find(c => c.id === item.cleanerId);
                                return (
                                <li key={item.id} className="p-4 bg-gray-50 rounded-lg border flex flex-col sm:flex-row sm:items-start sm:justify-between">
                                    <div className="flex items-start gap-4 flex-grow">
                                        {cleaner?.photoUrl && <img src={cleaner.photoUrl} alt={cleaner.name} className="w-16 h-16 rounded-lg object-cover hidden sm:block"/>}
                                        <div className="flex-grow">
                                            <div className="flex justify-between items-start">
                                                <div>
                                                    <p className="font-bold text-dark">{item.service}</p>
                                                    <p className="text-sm text-gray-600">with {item.cleanerName}</p>
                                                    <p className="text-sm text-gray-500">{item.date}</p>
                                                </div>
                                                <div className="text-right">
                                                    <p className="font-bold text-lg text-primary">₦{(item.totalAmount || item.amount).toLocaleString()}</p>
                                                    <span className={`text-xs font-bold px-2 py-1 rounded-full ${ item.status === 'Upcoming' ? 'bg-blue-100 text-blue-800' : item.status === 'Completed' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800' }`}>
                                                        {item.status}
                                                    </span>
                                                </div>
                                            </div>
                                            <div className="mt-2 text-xs">
                                                 <span className={`font-semibold px-2 py-0.5 rounded-full ${getPaymentStatusBadgeClass(item.paymentStatus)}`}>
                                                    {item.paymentMethod}: {item.paymentStatus}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="mt-4 sm:mt-0 sm:ml-4 flex flex-col items-stretch sm:items-end justify-start gap-2 flex-shrink-0">
                                         <button 
                                            onClick={() => handleMessageCleaner(item.cleanerId, item.cleanerName)}
                                            className="w-full sm:w-auto text-center bg-gray-100 text-primary px-3 py-1.5 rounded-md text-xs font-semibold hover:bg-gray-200 border border-gray-200"
                                         >
                                            Message Cleaner
                                         </button>

                                         {item.status === 'Upcoming' && <button onClick={() => setBookingToCancel(item)} className="w-full sm:w-auto text-center bg-red-100 text-red-700 px-3 py-1.5 rounded-md text-xs font-semibold hover:bg-red-200">Cancel Booking</button>}
                                         
                                         {item.status === 'Completed' && !item.reviewSubmitted && <button onClick={() => setBookingToReview(item)} className="w-full sm:w-auto text-center bg-yellow-100 text-yellow-800 px-3 py-1.5 rounded-md text-xs font-semibold hover:bg-yellow-200">Submit Review</button>}
                                         
                                         {item.status === 'Upcoming' && item.paymentMethod === 'Direct' && (
                                            <button onClick={() => onApproveJobCompletion(item.id)} className="w-full sm:w-auto text-center bg-green-600 text-white px-3 py-1.5 rounded-md text-xs font-semibold hover:bg-green-700">Mark as Completed</button>
                                         )}

                                         {item.status === 'Upcoming' && item.paymentMethod === 'Escrow' && item.paymentStatus === 'Confirmed' && !item.jobApprovedByClient && <button onClick={() => onApproveJobCompletion(item.id)} className="w-full sm:w-auto text-center bg-green-600 text-white px-3 py-1.5 rounded-md text-xs font-semibold hover:bg-green-700">Approve Job Completion</button>}
                                         
                                         {item.paymentMethod === 'Escrow' && item.paymentStatus === 'Pending Payment' && <button onClick={() => handleReceiptUploadClick(item.id)} className="w-full sm:w-auto text-center bg-blue-600 text-white px-3 py-1.5 rounded-md text-xs font-semibold hover:bg-blue-700">Upload Receipt</button>}
                                    </div>
                                </li>
                                )})}
                        </ul>
                    ) : (
                        <p className="text-sm text-gray-500 py-2">No bookings yet. Time to find a cleaner!</p>
                    )}
                </div>
            )}
             
            {activeTab === 'messages' && (
                <div className="bg-white p-6 rounded-lg shadow-md min-h-[600px]">
                    <ChatInterface currentUser={user} />
                </div>
            )}

            {activeTab === 'support' && (
                <SupportTicketSection userId={user.id} />
            )}

            {activeTab === 'profile' && (
                <div className="bg-white rounded-lg shadow-lg overflow-hidden">
                    <div className="p-6 sm:flex sm:items-center sm:justify-between bg-gray-50 border-b">
                        <div className="sm:flex sm:items-center sm:space-x-5">
                             <div className="relative">
                                <img className="h-20 w-20 rounded-full object-cover" src={profilePhotoPreview || 'https://avatar.iran.liara.run/public'} alt="Profile" />
                                {isEditingProfile && (
                                    <div className="absolute bottom-0 right-0">
                                        <label htmlFor="profilePhoto-upload" className="cursor-pointer bg-white rounded-full p-1 shadow-md hover:bg-gray-100">
                                            <PencilIcon className="w-4 h-4 text-primary"/>
                                        </label>
                                        <input id="profilePhoto-upload" name="profilePhoto-upload" type="file" className="sr-only" onChange={handleProfileFileChange} />
                                    </div>
                                )}
                            </div>
                            <div className="mt-4 text-center sm:mt-0 sm:text-left">
                                <p className="text-xl font-bold text-gray-900 sm:text-2xl">{profileDisplayName}</p>
                                <p className="text-sm font-medium text-gray-600">{profileFormData.email}</p>
                            </div>
                        </div>
                         <div className="mt-5 flex justify-center sm:mt-0">
                            {isEditingProfile ? (
                                <div className="flex gap-3">
                                    <button onClick={handleCancelProfile} type="button" className="rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50">Cancel</button>
                                    <button onClick={handleSaveProfile} type="button" className="rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-secondary focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary">Save Changes</button>
                                </div>
                            ) : (
                                <button onClick={() => setIsEditingProfile(true)} type="button" className="flex items-center gap-2 rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50">
                                    <PencilIcon className="w-4 h-4 text-gray-600"/>
                                    Edit Profile
                                </button>
                            )}
                        </div>
                    </div>

                    <div className="border-t border-gray-200 px-4 py-5 sm:p-0">
                        <dl className="sm:divide-y sm:divide-gray-200">
                            <div className="px-4 sm:px-6">
                                <h3 className="text-lg font-medium text-gray-900 mt-4">Personal Information</h3>
                                <ProfileField label="Full Name" value={profileFormData.fullName} isEditing={isEditingProfile}>{renderValueOrInput('fullName', 'text', { maxLength: 100 })}</ProfileField>
                                <ProfileField label="Phone Number" value={profileFormData.phoneNumber} isEditing={isEditingProfile}>{renderValueOrInput('phoneNumber', 'tel', { pattern: "[0-9]{10,11}", title: "Please enter a valid 10 or 11-digit phone number.", minLength: 10, maxLength: 11 })}</ProfileField>
                                <ProfileField label="Address" value={profileFormData.address} isEditing={isEditingProfile}>{isEditingProfile ? <textarea name="address" value={profileFormData.address} onChange={handleProfileInputChange} className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm" rows={3} maxLength={250} /> : profileFormData.address}</ProfileField>
                                
                                <ProfileField label="State" value={profileFormData.state} isEditing={isEditingProfile}>
                                    <select name="state" value={profileFormData.state} onChange={handleProfileInputChange} className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm">
                                        <option value="">Select State</option>
                                        {NIGERIA_LOCATIONS.map(s => <option key={s.name} value={s.name}>{s.name}</option>)}
                                    </select>
                                </ProfileField>

                                <ProfileField label="City" value={profileFormData.city === 'Other' && profileFormData.otherCity ? profileFormData.otherCity : profileFormData.city} isEditing={isEditingProfile}>
                                    <div className="w-full space-y-2">
                                        <select 
                                            name="city" 
                                            value={profileFormData.city} 
                                            onChange={handleProfileInputChange} 
                                            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm"
                                            disabled={!profileFormData.state}
                                        >
                                            <option value="">Select City</option>
                                            {cities.map(c => <option key={c} value={c}>{c}</option>)}
                                        </select>
                                        {profileFormData.city === 'Other' && (
                                            <input
                                                type="text"
                                                name="otherCity"
                                                value={profileFormData.otherCity || ''}
                                                onChange={handleProfileInputChange}
                                                placeholder="Specify city"
                                                className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm"
                                            />
                                        )}
                                    </div>
                                </ProfileField>

                                <ProfileField label="Gender" value={profileFormData.gender} isEditing={isEditingProfile}>
                                    <select name="gender" value={profileFormData.gender} onChange={handleProfileInputChange} className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm">
                                        <option>Male</option>
                                        <option>Female</option>
                                        <option>Other</option>
                                    </select>
                                </ProfileField>
                            </div>
                           
                            {profileFormData.clientType === 'Company' && (
                                 <div className="px-4 sm:px-6">
                                    <h3 className="text-lg font-medium text-gray-900 mt-6">Company Information</h3>
                                    <ProfileField label="Company Name" value={profileFormData.companyName} isEditing={isEditingProfile}>{renderValueOrInput('companyName', 'text', { maxLength: 100 })}</ProfileField>
                                    <ProfileField label="Company Address" value={profileFormData.companyAddress} isEditing={isEditingProfile}>{isEditingProfile ? <textarea name="companyAddress" value={profileFormData.companyAddress} onChange={handleProfileInputChange} className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm" rows={3} maxLength={250} /> : profileFormData.companyAddress}</ProfileField>
                                </div>
                            )}
                        </dl>
                    </div>
                </div>
            )}

             {bookingToCancel && (<CancellationConfirmationModal booking={bookingToCancel} onClose={() => setBookingToCancel(null)} onConfirm={(id) => { onCancelBooking(id); setBookingToCancel(null); }} />)}
             {bookingToReview && (<ReviewModal booking={bookingToReview} onClose={() => setBookingToReview(null)} onSubmit={(data) => { onReviewSubmit(bookingToReview.id, bookingToReview.cleanerId, data); setBookingToReview(null); }} />)}
        </div>
    );
};
