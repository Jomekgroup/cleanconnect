import React, { useState } from 'react';
import { Cleaner, User } from '../types';
import { XCircleIcon } from './icons';

interface BookingModalProps {
    cleaner: Cleaner;
    user: User;
    onClose: () => void;
    onConfirmBooking: (paymentMethod: 'Direct' | 'Escrow', cleaner: Cleaner) => void;
    onProceedToEscrow: (bookingData: { cleaner: Cleaner, totalAmount: number }) => void;
}

export const BookingModal: React.FC<BookingModalProps> = ({ cleaner, user, onClose, onConfirmBooking, onProceedToEscrow }) => {
    const [paymentMethod, setPaymentMethod] = useState<'Escrow' | 'Direct'>('Escrow');
    const baseAmount = cleaner.chargeHourly || cleaner.chargeDaily || cleaner.chargePerContract || 5000;
    const escrowFee = baseAmount * 0.10;
    const totalEscrowAmount = baseAmount + escrowFee;

    const handleConfirm = () => {
        if (paymentMethod === 'Direct') {
            onConfirmBooking('Direct', cleaner);
        } else {
            onProceedToEscrow({ cleaner, totalAmount: totalEscrowAmount });
        }
    };

    return (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4" aria-modal="true" role="dialog">
            <div className="bg-white rounded-2xl shadow-xl w-full max-w-md transform transition-all">
                <div className="p-6 relative">
                    <button onClick={onClose} className="absolute top-4 right-4 text-gray-400 hover:text-gray-600">
                        <XCircleIcon className="w-6 h-6" />
                    </button>
                    
                    <div className="text-center">
                        <h3 className="text-xl font-bold text-gray-900">Confirm Your Booking</h3>
                        <p className="mt-2 text-sm text-gray-500">You are booking <span className="font-bold">{cleaner.name}</span>.</p>
                    </div>

                    <div className="my-6 p-4 bg-light rounded-lg text-center">
                        <p className="text-sm text-gray-600">Cleaner's Charge</p>
                        <p className="text-3xl font-extrabold text-dark">₦{baseAmount.toLocaleString()}</p>
                    </div>

                    <div>
                        <h4 className="text-md font-semibold text-gray-800 mb-3">Select Payment Method</h4>
                        <div className="space-y-4">
                            <label className={`flex items-start p-4 border-2 rounded-lg cursor-pointer transition-all ${paymentMethod === 'Escrow' ? 'border-primary bg-green-50' : 'border-gray-200'}`}>
                                <input type="radio" name="paymentMethod" value="Escrow" checked={paymentMethod === 'Escrow'} onChange={() => setPaymentMethod('Escrow')} className="mt-1 h-4 w-4 text-primary border-gray-300 focus:ring-primary"/>
                                <div className="ml-3 text-sm">
                                    <p className="font-bold text-gray-900">Pay via Escrow</p>
                                    <p className="text-gray-500">Pay securely to CleanConnect. We hold the payment until you approve the job is complete. An extra 10% service fee applies.</p>
                                    <p className="font-semibold text-primary mt-1">Total: ₦{totalEscrowAmount.toLocaleString()} (₦{baseAmount.toLocaleString()} + ₦{escrowFee.toLocaleString()} fee)</p>
                                </div>
                            </label>
                            <label className={`flex items-start p-4 border-2 rounded-lg cursor-pointer transition-all ${paymentMethod === 'Direct' ? 'border-primary bg-green-50' : 'border-gray-200'}`}>
                                <input type="radio" name="paymentMethod" value="Direct" checked={paymentMethod === 'Direct'} onChange={() => setPaymentMethod('Direct')} className="mt-1 h-4 w-4 text-primary border-gray-300 focus:ring-primary"/>
                                <div className="ml-3 text-sm">
                                    <p className="font-bold text-gray-900">Pay Cleaner Directly</p>
                                    <p className="text-gray-500">Arrange payment directly with the cleaner upon job completion. CleanConnect is not liable for direct payments.</p>
                                     <p className="font-semibold text-primary mt-1">Total: ₦{baseAmount.toLocaleString()}</p>
                                </div>
                            </label>
                        </div>
                    </div>
                    
                    <div className="mt-8">
                        <button
                            onClick={handleConfirm}
                            className="w-full flex justify-center items-center rounded-md border border-transparent bg-primary px-4 py-3 text-base font-medium text-white shadow-sm hover:bg-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2"
                        >
                            {paymentMethod === 'Escrow' ? 'Proceed to Pay' : 'Confirm Booking'}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};