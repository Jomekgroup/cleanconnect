import React from 'react';
import { Receipt } from '../types';
import { XCircleIcon } from './icons';

interface ReceiptViewerModalProps {
    receipt: Receipt;
    onClose: () => void;
}

export const ReceiptViewerModal: React.FC<ReceiptViewerModalProps> = ({ receipt, onClose }) => {
    const isImage = receipt.dataUrl.startsWith('data:image');

    return (
        <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 p-4" aria-modal="true" role="dialog">
            <div className="bg-white rounded-2xl shadow-xl w-full max-w-2xl max-h-[90vh] flex flex-col transform transition-all">
                <div className="p-4 border-b flex justify-between items-center">
                    <h3 className="text-lg font-semibold text-gray-900">Receipt: {receipt.name}</h3>
                    <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
                        <XCircleIcon className="w-6 h-6" />
                    </button>
                </div>
                <div className="p-4 flex-grow overflow-auto flex items-center justify-center">
                    {isImage ? (
                        <img src={receipt.dataUrl} alt={receipt.name} className="max-w-full max-h-full object-contain" />
                    ) : (
                        <div className="text-center p-8">
                             <p className="text-gray-600 mb-4">This file is not an image and cannot be previewed directly.</p>
                             <a 
                                 href={receipt.dataUrl} 
                                 download={receipt.name}
                                 className="inline-block bg-primary text-white px-6 py-2 rounded-lg font-semibold hover:bg-secondary transition-colors"
                             >
                                 Download {receipt.name}
                             </a>
                        </div>
                    )}
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