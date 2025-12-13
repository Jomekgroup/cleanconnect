import React from 'react';
import { UserRole } from '../types';

interface RoleSelectionProps {
    onSelect: (role: UserRole) => void;
}

export const RoleSelection: React.FC<RoleSelectionProps> = ({ onSelect }) => {
    return (
        <div className="min-h-full flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
            <div className="max-w-md w-full space-y-8">
                <div className="text-center">
                    <h2 className="text-3xl font-extrabold text-dark">How would you like to join CleanConnect?</h2>
                    <p className="mt-2 text-sm text-gray-600">Choose your role to get started.</p>
                </div>
                <div className="mt-8 bg-white p-8 rounded-lg shadow-lg space-y-6">
                    <div 
                        onClick={() => onSelect('client')} 
                        className="p-6 border-2 border-gray-200 rounded-lg hover:bg-green-50 hover:border-primary cursor-pointer transition-all transform hover:scale-105"
                    >
                        <h3 className="text-lg font-bold text-primary">I'm a Client</h3>
                        <p className="text-sm text-gray-500 mt-1">I want to find and book trusted, top-rated cleaning professionals.</p>
                    </div>
                    <div 
                        onClick={() => onSelect('cleaner')} 
                        className="p-6 border-2 border-gray-200 rounded-lg hover:bg-green-50 hover:border-primary cursor-pointer transition-all transform hover:scale-105"
                    >
                        <h3 className="text-lg font-bold text-primary">I'm a Cleaner</h3>
                        <p className="text-sm text-gray-500 mt-1">I want to offer my services, connect with clients, and grow my business.</p>
                    </div>
                </div>
            </div>
        </div>
    );
};
