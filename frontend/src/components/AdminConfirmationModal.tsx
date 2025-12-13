import React from 'react';
import { XCircleIcon } from './icons';

interface AdminConfirmationModalProps {
    title: string;
    message: string;
    confirmText: string;
    onClose: () => void;
    onConfirm: () => void;
    confirmButtonClass?: string;
}

export const AdminConfirmationModal: React.FC<AdminConfirmationModalProps> = ({ title, message, confirmText, onClose, onConfirm, confirmButtonClass = 'bg-red-600 hover:bg-red-500' }) => {
    return (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4" aria-modal="true" role="dialog">
            <div className="bg-white rounded-2xl shadow-xl w-full max-w-md transform transition-all">
                <div className="p-6 relative">
                     <button onClick={onClose} className="absolute top-4 right-4 text-gray-400 hover:text-gray-600">
                        <XCircleIcon className="w-6 h-6" />
                    </button>
                    <div className="text-center">
                        <h3 className="mt-4 text-lg font-semibold text-gray-900">{title}</h3>
                        <p className="mt-2 text-sm text-gray-500">{message}</p>
                    </div>

                    <div className="mt-6 flex justify-center gap-4">
                        <button
                            onClick={onClose}
                            type="button"
                            className="rounded-md bg-white px-4 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50"
                        >
                            Cancel
                        </button>
                        <button
                            onClick={onConfirm}
                            type="button"
                            className={`rounded-md px-4 py-2 text-sm font-semibold text-white shadow-sm ${confirmButtonClass}`}
                        >
                            {confirmText}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};
