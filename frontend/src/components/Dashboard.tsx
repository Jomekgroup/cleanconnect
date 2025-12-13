
import React, { useState, useEffect, useRef } from 'react';
import { User, View, Receipt } from 'types';
import { PencilIcon, StarIcon, BriefcaseIcon, ChatBubbleLeftRightIcon, LifebuoyIcon } from './icons';
import { CLEANING_SERVICES } from '../constants/services';
import { CLIENT_LIMITS } from '../constants/subscriptions';
import { ChatInterface } from './ChatInterface';
import { apiService } from '../services/apiService'; 
import { SupportTicketSection } from './SupportTicketSection';
import { NIGERIA_LOCATIONS } from '../constants/locations';

interface DashboardProps {
    user: User;
    onUpdateUser: (user: User) => void;
    onNavigate: (view: View) => void;
    onUploadSubscriptionReceipt: (receipt: Receipt) => void;
    initialTab?: 'profile' | 'jobs' | 'reviews' | 'messages' | 'support';
}

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


export const Dashboard: React.FC<DashboardProps> = ({ user, onUpdateUser, onNavigate, onUploadSubscriptionReceipt, initialTab }) => {
    const [activeTab, setActiveTab] = useState<'profile' | 'jobs' | 'reviews' | 'messages' | 'support'>(initialTab || 'profile');
    const [isEditing, setIsEditing] = useState(false);
    const [formData, setFormData] = useState<any>(user);
    const [profilePhotoPreview, setProfilePhotoPreview] = useState<string | null>(null);
    const subReceiptInputRef = useRef<HTMLInputElement>(null);
    const [daysRemaining, setDaysRemaining] = useState<number | null>(null);
    const [cities, setCities] = useState<string[]>([]);

    const limit = user.subscriptionTier ? CLIENT_LIMITS[user.subscriptionTier] : 0;
    const currentClientsCount = user.monthlyNewClientsIds?.length || 0;
    const isLimitReached = user.subscriptionTier ? currentClientsCount >= limit : false;


    useEffect(() => {
        // When user data loads, set form data but convert 0s to empty strings for better editing UX
        const safeData = { ...user };
        if (safeData.experience === 0) safeData.experience = '' as any;
        if (safeData.chargeHourly === 0) safeData.chargeHourly = '' as any;
        if (safeData.chargeDaily === 0) safeData.chargeDaily = '' as any;
        if (safeData.chargePerContract === 0) safeData.chargePerContract = '' as any;

        setFormData(safeData); 
        
        if (user.profilePhoto && user.profilePhoto instanceof File) {
            setProfilePhotoPreview(URL.createObjectURL(user.profilePhoto));
        } else if (typeof user.profilePhoto === 'string') {
             setProfilePhotoPreview(user.profilePhoto);
        }

        if (user.subscriptionEndDate) {
            const today = new Date();
            const endDate = new Date(user.subscriptionEndDate);
            today.setHours(0, 0, 0, 0); // Normalize to the start of the day
            const timeDiff = endDate.getTime() - today.getTime();
            const remaining = Math.ceil(timeDiff / (1000 * 3600 * 24));
            setDaysRemaining(remaining);
        } else {
            setDaysRemaining(null);
        }
    }, [user]);

    // Update cities when state changes
    useEffect(() => {
        if (formData.state) {
            const selectedState = NIGERIA_LOCATIONS.find(s => s.name === formData.state);
            setCities(selectedState ? [...selectedState.towns, 'Other'] : ['Other']);
        } else {
            setCities([]);
        }
    }, [formData.state]);

    useEffect(() => {
        if (initialTab) setActiveTab(initialTab);
    }, [initialTab]);
    
    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
        const { name, value } = e.target;
        setFormData((prev: any) => {
            const updates: any = { ...prev, [name]: value };
            // If state changes, reset city
            if (name === 'state') {
                updates.city = '';
                updates.otherCity = '';
            }
            return updates;
        });
    };

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            const file = e.target.files[0];
            setFormData((prev: any) => ({...prev, profilePhoto: file }));
            setProfilePhotoPreview(URL.createObjectURL(file));
        }
    };
    
    const handleSave = () => {
        onUpdateUser(formData);
        setIsEditing(false);
    };

    const handleCancel = () => {
        setFormData(user);
        setIsEditing(false);
    };
    
    const handleReceiptUploadClick = () => {
        subReceiptInputRef.current?.click();
    };

    const handleSubReceiptFileSelected = (event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.files && event.target.files[0]) {
            const file = event.target.files[0];
            const reader = new FileReader();
            reader.onloadend = () => {
                if (reader.result) {
                    onUploadSubscriptionReceipt({ name: file.name, dataUrl: reader.result as string });
                }
            };
            reader.readAsDataURL(file);
        }
        if(event.target) {
            event.target.value = '';
        }
    };

    const handleMessageClient = async (clientId: string, clientName: string) => {
        try {
            await apiService.createChat(user.id, clientId, user.fullName, clientName);
            setActiveTab('messages');
        } catch (error) {
            alert('Could not start chat. Please try again.');
        }
    };
    
    const renderValueOrInput = (name: keyof User, type: 'text' | 'email' | 'tel' | 'number' = 'text', options: Record<string, any> = {}) => {
        return (
            <input
                type={type}
                name={name}
                id={name}
                value={formData[name] as string || ''}
                onChange={handleInputChange}
                className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm"
                {...options}
            />
        );
    };
    
    const locationString = formData.city === 'Other' && formData.otherCity ? `${formData.otherCity}, ${formData.state}` : `${formData.city}, ${formData.state}`;
    
    const reviews = user.reviewsData || [];
    const avgRating = reviews.length > 0 ? reviews.reduce((acc, r) => acc + r.rating, 0) / reviews.length : 0;
    const avgTimeliness = reviews.length > 0 ? reviews.reduce((acc, r) => acc + (r.timeliness || 0), 0) / reviews.length : 0;
    const avgThoroughness = reviews.length > 0 ? reviews.reduce((acc, r) => acc + (r.thoroughness || 0), 0) / reviews.length : 0;
    const avgConduct = reviews.length > 0 ? reviews.reduce((acc, r) => acc + (r.conduct || 0), 0) / reviews.length : 0;

    const bookings = user.bookingHistory || [];
    const sortedBookings = [...bookings].reverse();

    // Determine the display name (Company Name if applicable, else First Name for welcome)
    const displayName = user.cleanerType === 'Company' && user.companyName 
        ? user.companyName 
        : user.fullName.split(' ')[0];

    // Determine the name to display in profile header
    const profileDisplayName = formData.cleanerType === 'Company' && formData.companyName 
        ? formData.companyName 
        : formData.fullName;

    return (
        <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-12">
             <input
                type="file"
                ref={subReceiptInputRef}
                onChange={handleSubReceiptFileSelected}
                className="hidden"
                accept="image/*,.pdf"
            />
            
            <div className="flex flex-col sm:flex-row justify-between items-center mb-6 gap-4">
                <h1 className="text-3xl font-bold text-dark text-center sm:text-left">Welcome back, {displayName}!</h1>
            </div>

             {isLimitReached && (
                <div className="p-4 rounded-md mb-6 bg-red-100 border-red-200 text-red-800">
                    <h4 className="font-bold">Monthly Client Limit Reached!</h4>
                    <p className="text-sm">
                        You have reached your limit of <strong>{limit}</strong> new client{limit !== 1 ? 's' : ''} for this month on the <strong>{user.subscriptionTier}</strong> plan.
                    </p>
                    <div className="mt-2">
                        <p className="text-sm mb-2">To accept jobs from new clients, please upgrade your plan.</p>
                        <button onClick={() => onNavigate('subscription')} className="bg-red-600 text-white px-3 py-1.5 rounded-md text-sm font-semibold hover:bg-red-700">
                            Upgrade Subscription
                        </button>
                    </div>
                </div>
            )}
            {daysRemaining !== null && daysRemaining <= 7 && user.subscriptionTier !== 'Free' && (
                 <div className={`p-4 rounded-md mb-6 border ${daysRemaining <= 0 ? 'bg-red-100 border-red-200 text-red-800' : 'bg-yellow-100 border-yellow-200 text-yellow-800'}`}>
                    <div className="flex justify-between items-center">
                        <div>
                            <h4 className="font-bold">
                                {daysRemaining <= 0 ? 'Subscription Expired' : 'Subscription Expiring Soon'}
                            </h4>
                            <p className="text-sm">
                                {daysRemaining <= 0
                                    ? 'Your account has been reverted to the Free plan. Renew now to restore your premium features.'
                                    : `Your subscription expires in ${daysRemaining} day${daysRemaining !== 1 ? 's' : ''}. Renew now to avoid service interruption.`}
                            </p>
                        </div>
                        <button 
                            onClick={() => onNavigate('subscription')}
                            className={`px-4 py-2 text-sm font-semibold rounded-md shadow-sm ${daysRemaining <= 0 ? 'bg-red-600 hover:bg-red-700 text-white' : 'bg-yellow-500 hover:bg-yellow-600 text-white'}`}
                        >
                            Renew Subscription
                        </button>
                    </div>
                </div>
            )}
            {user.pendingSubscription && (
                <div className={`p-4 rounded-md mb-6 ${user.subscriptionReceipt ? 'bg-blue-100 text-blue-800' : 'bg-yellow-100 text-yellow-800'}`}>
                    <h4 className="font-bold">Subscription Upgrade Pending</h4>
                    <p className="text-sm">
                        Your request to upgrade to the <strong>{user.pendingSubscription}</strong> plan is being processed.
                    </p>
                    {!user.subscriptionReceipt ? (
                        <div className="mt-2">
                             <p className="text-sm mb-2">Please upload your payment receipt to continue.</p>
                             <button onClick={handleReceiptUploadClick} className="bg-yellow-500 text-white px-3 py-1.5 rounded-md text-sm font-semibold hover:bg-yellow-600">
                                Upload Receipt
                             </button>
                        </div>
                    ) : (
                         <p className="text-sm mt-2">Your receipt has been submitted. Your plan will be upgraded upon admin confirmation.</p>
                    )}
                </div>
            )}

            <div className="border-b border-gray-200 mb-6 overflow-x-auto">
                <nav className="-mb-px flex space-x-8" aria-label="Tabs">
                    <button onClick={() => setActiveTab('profile')} className={`${activeTab === 'profile' ? 'border-primary text-primary' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'} whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}>
                        My Profile
                    </button>
                    <button onClick={() => setActiveTab('jobs')} className={`${activeTab === 'jobs' ? 'border-primary text-primary' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'} whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}>
                        My Jobs & Payments
                    </button>
                    <button onClick={() => setActiveTab('reviews')} className={`${activeTab === 'reviews' ? 'border-primary text-primary' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'} whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}>
                        My Reviews & Ratings
                    </button>
                    <button onClick={() => setActiveTab('messages')} className={`${activeTab === 'messages' ? 'border-primary text-primary' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'} whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2`}>
                        <ChatBubbleLeftRightIcon className="w-4 h-4" />
                        Messages
                    </button>
                    <button onClick={() => setActiveTab('support')} className={`${activeTab === 'support' ? 'border-primary text-primary' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'} whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2`}>
                        <LifebuoyIcon className="w-4 h-4" />
                        Support
                    </button>
                </nav>
            </div>
            
            {activeTab === 'profile' && (
                <div className="bg-white rounded-lg shadow-lg overflow-hidden">
                    <div className="p-6 sm:flex sm:items-center sm:justify-between bg-gray-50 border-b">
                        <div className="sm:flex sm:items-center sm:space-x-5">
                             <div className="relative">
                                <img className="h-20 w-20 rounded-full object-cover" src={profilePhotoPreview || 'https://avatar.iran.liara.run/public'} alt="Profile" />
                                {isEditing && (
                                    <div className="absolute bottom-0 right-0">
                                        <label htmlFor="profilePhoto-upload" className="cursor-pointer bg-white rounded-full p-1 shadow-md hover:bg-gray-100">
                                            <PencilIcon className="w-4 h-4 text-primary"/>
                                        </label>
                                        <input id="profilePhoto-upload" name="profilePhoto-upload" type="file" className="sr-only" onChange={handleFileChange} />
                                    </div>
                                )}
                            </div>
                            <div className="mt-4 text-center sm:mt-0 sm:text-left">
                                <p className="text-xl font-bold text-gray-900 sm:text-2xl">{profileDisplayName}</p>
                                <p className="text-sm font-medium text-gray-600">{formData.email}</p>
                            </div>
                        </div>
                         <div className="mt-5 flex justify-center sm:mt-0">
                            {isEditing ? (
                                <div className="flex gap-3">
                                    <button onClick={handleCancel} type="button" className="rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50">Cancel</button>
                                    <button onClick={handleSave} type="button" className="rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-secondary focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary">Save Changes</button>
                                </div>
                            ) : (
                                <button onClick={() => setIsEditing(true)} type="button" className="flex items-center gap-2 rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50">
                                    <PencilIcon className="w-4 h-4 text-gray-600"/>
                                    Edit Profile
                                </button>
                            )}
                        </div>
                    </div>

                    <div className="border-t border-gray-200 px-4 py-5 sm:p-0">
                        <dl className="sm:divide-y sm:divide-gray-200">
                             <div className="px-4 sm:px-6">
                                <div className="py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:py-5 border-b border-gray-100">
                                    <dt className="text-sm font-medium text-gray-500">Subscription</dt>
                                    <dd className="mt-1 flex flex-col sm:flex-row sm:items-center sm:justify-between text-sm text-gray-900 sm:col-span-2 sm:mt-0">
                                        <div>
                                            <span className={`px-3 py-1 text-sm font-semibold rounded-full ${
                                                formData.subscriptionTier === 'Premium' ? 'bg-purple-100 text-purple-800' :
                                                formData.subscriptionTier === 'Pro' ? 'bg-indigo-100 text-indigo-800' :
                                                formData.subscriptionTier === 'Standard' ? 'bg-green-100 text-green-800' :
                                                'bg-gray-100 text-gray-800'
                                            }`}>
                                                {formData.subscriptionTier} Plan
                                            </span>
                                            {formData.subscriptionEndDate && (
                                                <p className="text-xs text-gray-500 mt-1">
                                                    Expires on: {new Date(formData.subscriptionEndDate).toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' })}
                                                </p>
                                            )}
                                        </div>
                                        <button onClick={() => onNavigate('subscription')} className="font-medium text-primary hover:text-secondary mt-2 sm:mt-0">
                                            Manage Subscription
                                        </button>
                                    </dd>
                                </div>
                            </div>
                            <div className="px-4 sm:px-6">
                                <h3 className="text-lg font-medium text-gray-900 mt-4">Personal Information</h3>
                            </div>
                             <div className="px-4 sm:px-6">
                                <ProfileField label="Full Name" value={formData.fullName} isEditing={isEditing}>{renderValueOrInput('fullName', 'text', { maxLength: 100 })}</ProfileField>
                                <ProfileField label="Phone Number" value={formData.phoneNumber} isEditing={isEditing}>{renderValueOrInput('phoneNumber', 'tel', { pattern: "[0-9]{10,11}", title: "Please enter a valid 10 or 11-digit phone number.", minLength: 10, maxLength: 11 })}</ProfileField>
                                <ProfileField label="Address" value={formData.address} isEditing={isEditing}>{isEditing ? <textarea name="address" value={formData.address} onChange={handleInputChange} className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm" rows={3} maxLength={250} /> : formData.address}</ProfileField>
                                
                                <ProfileField label="State" value={formData.state} isEditing={isEditing}>
                                    <select name="state" value={formData.state} onChange={handleInputChange} className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm">
                                        <option value="">Select State</option>
                                        {NIGERIA_LOCATIONS.map(s => <option key={s.name} value={s.name}>{s.name}</option>)}
                                    </select>
                                </ProfileField>

                                <ProfileField label="City" value={locationString} isEditing={isEditing}>
                                    <div className="w-full space-y-2">
                                        <select 
                                            name="city" 
                                            value={formData.city} 
                                            onChange={handleInputChange} 
                                            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm"
                                            disabled={!formData.state}
                                        >
                                            <option value="">Select City</option>
                                            {cities.map(c => <option key={c} value={c}>{c}</option>)}
                                        </select>
                                        {formData.city === 'Other' && (
                                            <input
                                                type="text"
                                                name="otherCity"
                                                value={formData.otherCity || ''}
                                                onChange={handleInputChange}
                                                placeholder="Specify city"
                                                className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm"
                                            />
                                        )}
                                    </div>
                                </ProfileField>

                                <ProfileField label="Gender" value={formData.gender} isEditing={isEditing}>
                                    <select name="gender" value={formData.gender} onChange={handleInputChange} className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm">
                                        <option>Male</option>
                                        <option>Female</option>
                                        <option>Other</option>
                                    </select>
                                </ProfileField>
                            </div>
                           
                            {formData.cleanerType === 'Company' && (
                                 <div className="px-4 sm:px-6">
                                    <h3 className="text-lg font-medium text-gray-900 mt-6">Company Information</h3>
                                    <ProfileField label="Company Name" value={formData.companyName} isEditing={isEditing}>{renderValueOrInput('companyName', 'text', { maxLength: 100 })}</ProfileField>
                                    <ProfileField label="Company Address" value={formData.companyAddress} isEditing={isEditing}>{isEditing ? <textarea name="companyAddress" value={formData.companyAddress} onChange={handleInputChange} className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm" rows={3} maxLength={250} /> : formData.companyAddress}</ProfileField>
                                </div>
                            )}

                             <div className="px-4 sm:px-6">
                                <h3 className="text-lg font-medium text-gray-900 mt-6">Professional Details</h3>
                                <ProfileField label="Bio" value={formData.bio} isEditing={isEditing}>{isEditing ? <textarea name="bio" value={formData.bio} onChange={handleInputChange} className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm" rows={4} maxLength={300}/> : formData.bio}</ProfileField>
                                <ProfileField label="Years of Experience" value={formData.experience} isEditing={isEditing}>{renderValueOrInput('experience', 'number', { min: 0 })}</ProfileField>
                                <ProfileField label="Services Offered" value={formData.services} isEditing={isEditing}>
                                    <div className="w-full">
                                        <select
                                            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm mb-2"
                                            onChange={(e) => {
                                                const service = e.target.value;
                                                if (service && !formData.services?.includes(service)) {
                                                    setFormData((prev: any) => ({...prev, services: [...(prev.services || []), service]}));
                                                }
                                                e.target.value = "";
                                            }}
                                        >
                                             <option value="">-- Add a service --</option>
                                             {CLEANING_SERVICES.filter(s => !formData.services?.includes(s)).map(service => (
                                                <option key={service} value={service}>{service}</option>
                                             ))}
                                        </select>
                                         <div className="flex flex-wrap gap-2">
                                            {formData.services?.map((s: string) => (
                                                <span key={s} className="flex items-center bg-green-100 text-primary text-xs font-semibold px-2.5 py-1 rounded-full">
                                                    {s}
                                                    {isEditing && (
                                                        <button 
                                                            onClick={() => setFormData((prev: any) => ({...prev, services: prev.services?.filter((service: string) => service !== s)}))}
                                                            className="ml-2 text-primary hover:text-red-500"
                                                        >
                                                            &times;
                                                        </button>
                                                    )}
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                </ProfileField>
                            </div>

                            <div className="px-4 sm:px-6">
                                <h3 className="text-lg font-medium text-gray-900 mt-6">Pricing</h3>
                                <p className="mt-1 text-sm text-gray-500 mb-4">Set your rates. You can leave fields blank if they don't apply.</p>
                                
                                <ProfileField label="Charge per Hour (₦)" value={formData.chargeHourly ? `₦${formData.chargeHourly.toLocaleString()}` : ''} isEditing={isEditing}>
                                    {renderValueOrInput('chargeHourly', 'number', { min: 0, placeholder: 'e.g. 3000' })}
                                </ProfileField>
                                
                                <ProfileField label="Charge per Day (₦)" value={formData.chargeDaily ? `₦${formData.chargeDaily.toLocaleString()}` : ''} isEditing={isEditing}>
                                    {renderValueOrInput('chargeDaily', 'number', { min: 0, placeholder: 'e.g. 15000' })}
                                </ProfileField>

                                <ProfileField label="Charge per Contract (₦)" value={formData.chargePerContractNegotiable ? 'Negotiable' : (formData.chargePerContract ? `₦${formData.chargePerContract.toLocaleString()}` : '')} isEditing={isEditing}>
                                    <div className="flex flex-col gap-2 w-full">
                                        <div className="flex items-center">
                                            <input
                                                type="checkbox"
                                                id="negotiable"
                                                name="chargePerContractNegotiable"
                                                checked={formData.chargePerContractNegotiable || false}
                                                onChange={(e) => {
                                                    const checked = e.target.checked;
                                                    setFormData((prev: any) => ({ 
                                                        ...prev, 
                                                        chargePerContractNegotiable: checked,
                                                        chargePerContract: checked ? '' : prev.chargePerContract 
                                                    }));
                                                }}
                                                className="h-4 w-4 text-primary focus:ring-secondary border-gray-300 rounded"
                                            />
                                            <label htmlFor="negotiable" className="ml-2 block text-sm text-gray-700">Negotiable</label>
                                        </div>
                                        {!formData.chargePerContractNegotiable && (
                                            <input
                                                type="number"
                                                name="chargePerContract"
                                                value={formData.chargePerContract || ''}
                                                onChange={handleInputChange}
                                                placeholder="e.g. 150000"
                                                className="block w-full rounded-md border-gray-300 shadow-sm focus:border-primary focus:ring-primary sm:text-sm"
                                            />
                                        )}
                                    </div>
                                </ProfileField>
                            </div>

                            <div className="px-4 sm:px-6">
                                <h3 className="text-lg font-medium text-gray-900 mt-6">Payment Information</h3>
                                <ProfileField label="Bank Name" value={formData.bankName} isEditing={isEditing}>{renderValueOrInput('bankName', 'text', { maxLength: 50 })}</ProfileField>
                                <ProfileField label="Account Number" value={formData.accountNumber} isEditing={isEditing}>{renderValueOrInput('accountNumber', 'text', { pattern: "[0-9]{10}", title: "Please enter your 10-digit NUBAN account number.", minLength: 10, maxLength: 10 })}</ProfileField>
                            </div>
                        </dl>
                    </div>
                </div>
            )}
            
            {activeTab === 'jobs' && (
                <div className="bg-white rounded-lg shadow-lg overflow-hidden p-6">
                    <h2 className="text-2xl font-bold text-dark mb-6 flex items-center gap-2">
                        <BriefcaseIcon className="w-6 h-6 text-primary"/>
                        My Jobs & Payment History
                    </h2>
                    
                    {sortedBookings.length > 0 ? (
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-200">
                                <thead className="bg-gray-50">
                                    <tr>
                                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Client</th>
                                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Service</th>
                                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Amount</th>
                                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Job Status</th>
                                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Payment Status</th>
                                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="bg-white divide-y divide-gray-200">
                                    {sortedBookings.map((booking) => (
                                        <tr key={booking.id}>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <div className="text-sm font-medium text-gray-900">{booking.clientName}</div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <div className="text-sm text-gray-500">{booking.service}</div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <div className="text-sm text-gray-500">{booking.date}</div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <div className="text-sm font-bold text-dark">₦{booking.amount.toLocaleString()}</div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                 <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                                    booking.status === 'Completed' ? 'bg-green-100 text-green-800' :
                                                    booking.status === 'Cancelled' ? 'bg-red-100 text-red-800' :
                                                    'bg-blue-100 text-blue-800'
                                                }`}>
                                                    {booking.status}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <div className="text-sm text-gray-500 flex flex-col">
                                                    <span>Method: {booking.paymentMethod}</span>
                                                    <span className={`text-xs font-bold ${
                                                        booking.paymentStatus === 'Paid' ? 'text-green-600' :
                                                        booking.paymentStatus === 'Confirmed' ? 'text-teal-600' :
                                                        booking.paymentStatus === 'Pending Payout' ? 'text-purple-600' :
                                                        'text-yellow-600'
                                                    }`}>
                                                        {booking.paymentStatus}
                                                    </span>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <button 
                                                    onClick={() => handleMessageClient(booking.clientId, booking.clientName)}
                                                    className="bg-primary text-white px-3 py-1 rounded-md text-xs font-semibold hover:bg-secondary flex items-center gap-1"
                                                >
                                                    <ChatBubbleLeftRightIcon className="w-3 h-3" />
                                                    Message
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                         <div className="text-center py-10">
                            <BriefcaseIcon className="mx-auto h-12 w-12 text-gray-400" />
                            <h3 className="mt-2 text-sm font-medium text-gray-900">No jobs yet</h3>
                            <p className="mt-1 text-sm text-gray-500">When you get booked, your jobs will appear here.</p>
                        </div>
                    )}
                </div>
            )}

            {activeTab === 'reviews' && (
                 <div className="bg-white rounded-lg shadow-lg p-6">
                     <h2 className="text-2xl font-bold text-dark mb-4">My Reviews & Ratings</h2>
                     <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8 text-center">
                        <div className="p-4 bg-light rounded-lg">
                            <p className="text-sm text-gray-500">Overall Rating</p>
                            <div className="flex items-center justify-center mt-1">
                                <StarIcon className="w-6 h-6 text-yellow-400"/>
                                <p className="text-3xl font-bold ml-1">{avgRating.toFixed(1)}</p>
                            </div>
                        </div>
                        <div className="p-4 bg-light rounded-lg">
                            <p className="text-sm text-gray-500">Timeliness</p>
                            <p className="text-3xl font-bold mt-1">{avgTimeliness.toFixed(1)}</p>
                        </div>
                        <div className="p-4 bg-light rounded-lg">
                            <p className="text-sm text-gray-500">Thoroughness</p>
                            <p className="text-3xl font-bold mt-1">{avgThoroughness.toFixed(1)}</p>
                        </div>
                        <div className="p-4 bg-light rounded-lg">
                            <p className="text-sm text-gray-500">Conduct</p>
                            <p className="text-3xl font-bold mt-1">{avgConduct.toFixed(1)}</p>
                        </div>
                     </div>
                     <h3 className="text-xl font-semibold text-dark mb-4">Client Feedback ({reviews.length})</h3>
                      {reviews.length > 0 ? (
                        <div className="space-y-4 max-h-96 overflow-y-auto pr-2">
                            {reviews.map((review, index) => (
                                <div key={index} className="p-4 border rounded-lg bg-gray-50">
                                    <div className="flex justify-between items-center">
                                        <p className="font-semibold">{review.reviewerName}</p>
                                        <div className="flex items-center">
                                            <StarIcon className="w-5 h-5 text-yellow-400" />
                                            <span className="ml-1 font-bold">{review.rating.toFixed(1)}</span>
                                        </div>
                                    </div>
                                    {review.comment && <p className="text-sm text-gray-600 mt-2 italic">"{review.comment}"</p>}
                                </div>
                            ))}
                        </div>
                      ) : (
                        <p className="text-gray-500">You have not received any reviews yet.</p>
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
        </div>
    );
};
