
import React from 'react';
import { GoogleIcon, AppleIcon, XCircleIcon, UserIcon } from './icons';

interface SocialAccountSelectorModalProps {
    provider: 'google' | 'apple';
    onClose: () => void;
    onSelect: (email: string, name: string) => void;
}

export const SocialAccountSelectorModal: React.FC<SocialAccountSelectorModalProps> = ({ provider, onClose, onSelect }) => {
    // Mock detected accounts based on provider
    const accounts = provider === 'google' ? [
        { name: 'Jane Doe', email: 'jane.doe@gmail.com', avatar: 'https://avatar.iran.liara.run/public/girl' },
        { name: 'J. Doe Business', email: 'j.doe.biz@gmail.com', avatar: null }
    ] : [
        { name: 'Jane Doe', email: 'jane@icloud.com', avatar: 'https://avatar.iran.liara.run/public/girl' }
    ];

    return (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
            <div className="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden transform transition-all scale-100">
                <div className="p-6">
                    <div className="flex justify-between items-center mb-6">
                        <div className="flex items-center gap-2">
                            {provider === 'google' ? <GoogleIcon /> : <AppleIcon />}
                            <span className="font-semibold text-gray-700">Sign in with {provider === 'google' ? 'Google' : 'Apple'}</span>
                        </div>
                        <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
                            <XCircleIcon className="w-6 h-6" />
                        </button>
                    </div>

                    <div className="space-y-1">
                        <h3 className="text-xl font-medium text-center text-gray-900">Choose an account</h3>
                        <p className="text-center text-sm text-gray-500 pb-6">to continue to CleanConnect</p>
                        
                        <div className="space-y-2">
                            {accounts.map((acc) => (
                                <button
                                    key={acc.email}
                                    onClick={() => onSelect(acc.email, acc.name)}
                                    className="w-full flex items-center p-3 hover:bg-gray-50 rounded-lg border border-transparent hover:border-gray-200 transition-all group"
                                >
                                    <div className="h-10 w-10 rounded-full overflow-hidden flex-shrink-0 bg-gray-200 flex items-center justify-center text-gray-500">
                                        {acc.avatar ? <img src={acc.avatar} alt={acc.name} className="h-full w-full object-cover"/> : <UserIcon className="w-6 h-6"/>}
                                    </div>
                                    <div className="ml-3 text-left">
                                        <p className="text-sm font-semibold text-gray-900 group-hover:text-primary">{acc.name}</p>
                                        <p className="text-xs text-gray-500">{acc.email}</p>
                                    </div>
                                </button>
                            ))}
                            
                            <div className="border-t border-gray-100 my-2 pt-2">
                                <button
                                    onClick={() => onSelect(`new.user.${Date.now()}@${provider === 'google' ? 'gmail.com' : 'icloud.com'}`, 'New User')}
                                    className="w-full flex items-center p-3 hover:bg-gray-50 rounded-lg border border-transparent hover:border-gray-200 transition-all"
                                >
                                    <div className="h-10 w-10 rounded-full flex-shrink-0 bg-gray-100 flex items-center justify-center text-gray-500">
                                        <UserIcon className="w-5 h-5"/>
                                    </div>
                                    <div className="ml-3 text-left">
                                        <p className="text-sm font-medium text-gray-900">Use another account</p>
                                    </div>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
                <div className="bg-gray-50 px-6 py-4 text-xs text-gray-500 text-center border-t">
                    To continue, {provider === 'google' ? 'Google' : 'Apple'} will share your name, email address, and language preference with CleanConnect.
                </div>
            </div>
        </div>
    );
};
