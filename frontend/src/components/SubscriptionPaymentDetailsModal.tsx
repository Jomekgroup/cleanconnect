import React from 'react';
import { SubscriptionPlan } from '../types';
import { XCircleIcon } from './icons';

interface SubscriptionPaymentDetailsModalProps {
    plan: SubscriptionPlan;
    onClose: () => void;
    onConfirm: (plan: SubscriptionPlan) => void;
}

export const SubscriptionPaymentDetailsModal: React.FC<SubscriptionPaymentDetailsModalProps> = ({ plan, onClose, onConfirm }) => {
    const accountDetails = {
        accountNumber: '4092144856',
        accountName: 'Clean Connect',
        bank: 'Polaris Bank'
    };
    
    const amount = plan.priceMonthly; // Assuming monthly for simplicity in this flow

    return (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4" aria-modal="true" role="dialog">
            <div className="bg-white rounded-2xl shadow-xl w-full max-w-md transform transition-all">
                <div className="p-6 relative">
                    <button onClick={onClose} className="absolute top-4 right-4 text-gray-400 hover:text-gray-600">
                        <XCircleIcon className="w-6 h-6" />
                    </button>
                    
                    <div className="text-center">
                        <h3 className="text-xl font-bold text-gray-900">Subscription Payment</h3>
                        <p className="mt-2 text-sm text-gray-500">To upgrade to the <span className="font-bold">{plan.name}</span> plan, please make a payment of <span className="font-bold text-lg text-dark">₦{amount.toLocaleString()}</span> to the account below.</p>
                    </div>

                    <div className="my-6 p-6 bg-light rounded-lg border border-primary/20">
                        <h4 className="font-semibold text-center text-dark mb-4">Account Details</h4>
                        <div className="space-y-2 text-sm">
                            <div className="flex justify-between">
                                <span className="text-gray-500">Bank Name:</span>
                                <span className="font-medium text-dark">{accountDetails.bank}</span>
                            </div>
                             <div className="flex justify-between">
                                <span className="text-gray-500">Account Name:</span>
                                <span className="font-medium text-dark">{accountDetails.accountName}</span>
                            </div>
                             <div className="flex justify-between">
                                <span className="text-gray-500">Account Number:</span>
                                <span className="font-medium text-dark">{accountDetails.accountNumber}</span>
                            </div>
                        </div>
                    </div>
                    
                    <p className="text-xs text-center text-gray-500">After payment, confirm below. You will then be prompted to upload your receipt from your dashboard.</p>

                    <div className="mt-6">
                        <button
                            onClick={() => onConfirm(plan)}
                            className="w-full flex justify-center items-center rounded-md border border-transparent bg-primary px-4 py-3 text-base font-medium text-white shadow-sm hover:bg-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2"
                        >
                           I've Made Payment
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};