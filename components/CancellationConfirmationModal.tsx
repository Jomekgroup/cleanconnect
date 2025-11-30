import React from 'react';
import { Booking } from '../types';
import { XCircleIcon } from './icons';

interface CancellationConfirmationModalProps {
    booking: Booking;
    onClose: () => void;
    onConfirm: (bookingId: string) => void;
}

export const CancellationConfirmationModal: React.FC<CancellationConfirmationModalProps> = ({ booking, onClose, onConfirm }) => {
    return (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4" aria-modal="true" role="dialog">
            <div className="bg-white rounded-2xl shadow-xl w-full max-w-md transform transition-all">
                <div className="p-6 relative">
                    <button onClick={onClose} className="absolute top-4 right-4 text-gray-400 hover:text-gray-600">
                        <XCircleIcon className="w-6 h-6" />
                    </button>

                    <div className="text-center">
                        <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100">
                            <svg className="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" aria-hidden="true">
                                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                            </svg>
                        </div>
                        <h3 className="mt-4 text-lg font-semibold text-gray-900">Cancel Booking</h3>
                        <p className="mt-2 text-sm text-gray-500">
                            Are you sure you want to cancel your booking for <span className="font-bold">{booking.service}</span> with <span className="font-bold">{booking.cleanerName}</span> on <span className="font-bold">{booking.date}</span>?
                        </p>
                        <p className="mt-1 text-xs text-gray-500">This action cannot be undone.</p>
                    </div>

                    <div className="mt-6 flex justify-center gap-4">
                        <button
                            onClick={onClose}
                            type="button"
                            className="rounded-md bg-white px-4 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50"
                        >
                            Go Back
                        </button>
                        <button
                            onClick={() => onConfirm(booking.id)}
                            type="button"
                            className="rounded-md bg-red-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-red-500"
                        >
                            Yes, Cancel Booking
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};
