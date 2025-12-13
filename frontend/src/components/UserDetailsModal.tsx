
import React from 'react';
import { User } from '../types';
import { XCircleIcon, EyeIcon } from './icons';

interface UserDetailsModalProps {
    user: User;
    onClose: () => void;
}

const DetailRow: React.FC<{ label: string; value?: string | number | null | string[] }> = ({ label, value }) => (
    <div className="grid grid-cols-3 gap-4 py-2">
        <dt className="text-sm font-medium text-gray-500 col-span-1">{label}</dt>
        <dd className="text-sm text-gray-900 col-span-2">
            {Array.isArray(value) ? (
                <div className="flex flex-wrap gap-1">
                    {value.length > 0 ? value.map(item => (
                        <span key={item} className="bg-green-100 text-primary text-xs font-semibold px-2 py-0.5 rounded-full">{item}</span>
                    )) : 'N/A'}
                </div>
            ) : (value || 'N/A')}
        </dd>
    </div>
);

const DocumentRow: React.FC<{ label: string; doc?: File | string }> = ({ label, doc }) => {
    if (!doc) return <DetailRow label={label} value="Not Uploaded" />;
    
    // For demo purposes, if it's a File object (not uploaded to cloud), create a local URL.
    // In production with backend, this would be a URL string.
    const url = doc instanceof File ? URL.createObjectURL(doc) : doc;
    
    return (
        <div className="grid grid-cols-3 gap-4 py-2 items-center">
            <dt className="text-sm font-medium text-gray-500 col-span-1">{label}</dt>
            <dd className="text-sm text-primary col-span-2">
                <a href={url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 hover:underline">
                    <EyeIcon className="w-4 h-4" />
                    View Document
                </a>
            </dd>
        </div>
    );
};

export const UserDetailsModal: React.FC<UserDetailsModalProps> = ({ user, onClose }) => {
    const isCleaner = user.role === 'cleaner';
    const locationString = user.city === 'Other' && user.otherCity ? user.otherCity : user.city;

    return (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4" aria-modal="true" role="dialog">
            <div className="bg-white rounded-2xl shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto transform transition-all">
                <div className="p-6 sticky top-0 bg-white border-b z-10">
                    <button onClick={onClose} className="absolute top-4 right-4 text-gray-400 hover:text-gray-600">
                        <XCircleIcon className="w-6 h-6" />
                    </button>
                    <div className="flex items-center space-x-4">
                        <img className="h-16 w-16 rounded-full object-cover" src={user.profilePhoto instanceof File ? URL.createObjectURL(user.profilePhoto) : (typeof user.profilePhoto === 'string' ? user.profilePhoto : 'https://avatar.iran.liara.run/public')} alt="Profile"/>
                        <div>
                            <h3 className="text-xl font-bold text-gray-900">{user.fullName}</h3>
                            <p className="text-sm text-gray-500 capitalize">{user.role} - {user.clientType || user.cleanerType}</p>
                        </div>
                    </div>
                </div>

                <div className="p-6">
                    <div>
                        <h4 className="font-semibold text-dark mb-2">Contact & Personal Information</h4>
                        <dl className="divide-y divide-gray-200">
                            <DetailRow label="Email" value={user.email} />
                            <DetailRow label="Phone" value={user.phoneNumber} />
                            <DetailRow label="Address" value={`${user.address}, ${locationString}, ${user.state}`} />
                            <DetailRow label="Gender" value={user.gender} />
                            <DetailRow label="Status" value={user.isSuspended ? 'Suspended' : 'Active'} />
                        </dl>
                    </div>

                    {(user.clientType === 'Company' || user.cleanerType === 'Company') && (
                        <div className="mt-6">
                            <h4 className="font-semibold text-dark mb-2">Company Information</h4>
                            <dl className="divide-y divide-gray-200">
                                <DetailRow label="Company Name" value={user.companyName} />
                                <DetailRow label="Company Address" value={user.companyAddress} />
                            </dl>
                        </div>
                    )}

                    {isCleaner && (
                        <>
                            <div className="mt-6">
                                <h4 className="font-semibold text-dark mb-2">Professional Profile</h4>
                                <dl className="divide-y divide-gray-200">
                                    <DetailRow label="Experience" value={`${user.experience} years`} />
                                    <DetailRow label="Bio" value={user.bio} />
                                    <DetailRow label="Services" value={user.services} />
                                </dl>
                            </div>
                            <div className="mt-6">
                                <h4 className="font-semibold text-dark mb-2">Pricing & Payment</h4>
                                <dl className="divide-y divide-gray-200">
                                    <DetailRow label="Hourly Rate" value={user.chargeHourly ? `₦${user.chargeHourly.toLocaleString()}` : 'N/A'} />
                                    <DetailRow label="Daily Rate" value={user.chargeDaily ? `₦${user.chargeDaily.toLocaleString()}` : 'N/A'} />
                                    <DetailRow label="Contract Rate" value={user.chargePerContractNegotiable ? 'Negotiable' : user.chargePerContract ? `₦${user.chargePerContract.toLocaleString()}`: 'N/A' } />
                                    <DetailRow label="Bank Name" value={user.bankName} />
                                    <DetailRow label="Account Number" value={user.accountNumber} />
                                    <DetailRow label="Subscription Tier" value={user.subscriptionTier} />
                                </dl>
                            </div>
                        </>
                    )}
                    
                    <div className="mt-6">
                        <h4 className="font-semibold text-dark mb-2">Verification Documents</h4>
                        <dl className="divide-y divide-gray-200">
                            <DocumentRow label="Government ID" doc={user.governmentId} />
                            {user.cleanerType === 'Company' && <DocumentRow label="Business Registration" doc={user.businessRegDoc} />}
                        </dl>
                    </div>

                    <div className="mt-6">
                        <h4 className="font-semibold text-dark mb-2">Booking History</h4>
                        {user.bookingHistory && user.bookingHistory.length > 0 ? (
                             <ul className="space-y-2 max-h-48 overflow-y-auto">
                                {user.bookingHistory.map((b) => (
                                    <li key={b.id} className="p-2 bg-gray-50 rounded-md text-sm">
                                        <div className="flex justify-between font-medium"><span>{b.service}</span><span>₦{b.amount.toLocaleString()}</span></div>
                                        <div className="flex justify-between text-xs text-gray-500"><span>{isCleaner ? `for ${b.clientName}` : `with ${b.cleanerName}`}</span><span>{b.date} - {b.status}</span></div>
                                    </li>
                                ))}
                            </ul>
                        ): <p className="text-sm text-gray-500">No bookings yet.</p>}
                    </div>

                </div>
                 <div className="p-4 bg-gray-50 border-t flex justify-end">
                    <button
                        onClick={onClose}
                        type="button"
                        className="rounded-md bg-white px-4 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50"
                    >
                        Close
                    </button>
                </div>
            </div>
        </div>
    );
};
