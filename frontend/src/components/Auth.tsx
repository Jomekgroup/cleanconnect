
import React, { useState, useEffect } from 'react';
import { User, View, UserRole } from '../types';
import { GoogleIcon, AppleIcon, EyeIcon, EyeSlashIcon } from './icons';
import { SocialAccountSelectorModal } from './SocialAccountSelectorModal';

interface AuthProps {
    initialTab: 'login' | 'signup';
    onNavigate: (v: View) => void;
    onLoginAttempt: (email: string, password?: string) => void;
    onSocialAuth: (provider: 'google' | 'apple', email?: string, name?: string, flow?: 'login' | 'signup') => void;
    onInitialSignup: (email: string, password: string) => void;
    authMessage: { type: 'success' | 'error', text: string } | null;
    onAuthMessageDismiss: () => void;
}

interface LoginTabProps {
    email: string;
    setEmail: (email: string) => void;
    password: string;
    setPassword: (password: string) => void;
    handleLogin: () => void;
    onSocialClick: (provider: 'google' | 'apple') => void;
    onForgotPasswordClick: () => void;
}

const LoginTab: React.FC<LoginTabProps> = ({ email, setEmail, password, setPassword, handleLogin, onSocialClick, onForgotPasswordClick }) => {
    const [showPassword, setShowPassword] = useState(false);
    return (
    <div>
        <form onSubmit={(e) => { e.preventDefault(); handleLogin(); }}>
            <div className="space-y-4">
                <div>
                    <label htmlFor="email" className="block text-sm font-medium text-gray-700">Email address</label>
                    <input 
                        type="email" 
                        id="email" 
                        autoComplete="email" 
                        required 
                        className="mt-1 block w-full px-3 py-2 border border-gray-600 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-dark text-light" 
                        placeholder="you@example.com"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                    />
                </div>
                <div>
                    <label htmlFor="password"className="block text-sm font-medium text-gray-700">Password</label>
                    <div className="relative mt-1">
                        <input 
                            type={showPassword ? 'text' : 'password'}
                            id="password" 
                            autoComplete="current-password" 
                            required
                            minLength={8}
                            title="Password must be at least 8 characters long."
                            className="block w-full px-3 py-2 border border-gray-600 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-dark text-light" 
                            placeholder="••••••••"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                        />
                        <div className="absolute inset-y-0 right-0 pr-3 flex items-center">
                             <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                className="text-gray-400 hover:text-gray-200 focus:outline-none"
                                aria-label={showPassword ? "Hide password" : "Show password"}
                            >
                                {showPassword ? <EyeSlashIcon className="h-5 w-5" /> : <EyeIcon className="h-5 w-5" />}
                            </button>
                        </div>
                    </div>
                </div>
                <div className="flex items-center justify-between">
                    <div className="flex items-center">
                        <input id="remember-me" name="remember-me" type="checkbox" className="h-4 w-4 text-primary focus:ring-secondary border-gray-300 rounded" />
                        <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-900">Remember me</label>
                    </div>
                    <div className="text-sm">
                        <button type="button" onClick={onForgotPasswordClick} className="font-medium text-primary hover:text-secondary">Forgot your password?</button>
                    </div>
                </div>
                <div>
                    <button type="submit" className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary hover:bg-secondary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary">
                        Sign in
                    </button>
                </div>
            </div>
        </form>
         <div className="mt-6">
            <div className="relative">
                <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-gray-300"></div>
                </div>
                <div className="relative flex justify-center text-sm">
                    <span className="px-2 bg-white text-gray-500">Or continue with</span>
                </div>
            </div>
            <div className="mt-6 grid grid-cols-2 gap-3">
                <button onClick={() => onSocialClick('google')} className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 hover:text-gray-800 transition-colors"><span className="sr-only">Sign in with Google</span><GoogleIcon /></button>
                <button onClick={() => onSocialClick('apple')} className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 hover:text-gray-800 transition-colors"><span className="sr-only">Sign in with Apple</span><AppleIcon /></button>
            </div>
        </div>
    </div>
    );
};
interface SignupTabProps {
    onInitialSignup: (email: string, password: string) => void;
    onSocialClick: (provider: 'google' | 'apple') => void;
}

const SignupTab: React.FC<SignupTabProps> = ({ onInitialSignup, onSocialClick }) => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (password !== confirmPassword) {
            alert("Passwords do not match.");
            return;
        }
        onInitialSignup(email, password);
    };

    return (
        <div>
            <form onSubmit={handleSubmit}>
                <div className="space-y-4">
                    <div>
                        <label htmlFor="signup-email" className="block text-sm font-medium text-gray-700">Email address</label>
                        <input type="email" id="signup-email" value={email} onChange={(e) => setEmail(e.target.value)} required className="mt-1 block w-full px-3 py-2 border border-gray-600 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-dark text-light" placeholder="you@example.com" />
                    </div>
                    <div>
                        <label htmlFor="signup-password"className="block text-sm font-medium text-gray-700">Password</label>
                        <div className="relative mt-1">
                            <input
                                type={showPassword ? 'text' : 'password'}
                                id="signup-password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                required
                                minLength={8}
                                pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}"
                                title="Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number."
                                className="block w-full px-3 py-2 border border-gray-600 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-dark text-light"
                                placeholder="••••••••"
                            />
                             <div className="absolute inset-y-0 right-0 pr-3 flex items-center">
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="text-gray-400 hover:text-gray-200 focus:outline-none"
                                    aria-label={showPassword ? "Hide password" : "Show password"}
                                >
                                    {showPassword ? <EyeSlashIcon className="h-5 w-5" /> : <EyeIcon className="h-5 w-5" />}
                                </button>
                            </div>
                        </div>
                    </div>
                     <div>
                        <label htmlFor="signup-confirm-password"className="block text-sm font-medium text-gray-700">Confirm Password</label>
                         <div className="relative mt-1">
                            <input
                                type={showConfirmPassword ? 'text' : 'password'}
                                id="signup-confirm-password"
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                required
                                minLength={8}
                                className="block w-full px-3 py-2 border border-gray-600 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-dark text-light"
                                placeholder="••••••••"
                            />
                             <div className="absolute inset-y-0 right-0 pr-3 flex items-center">
                                <button
                                    type="button"
                                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                    className="text-gray-400 hover:text-gray-200 focus:outline-none"
                                    aria-label={showConfirmPassword ? "Hide password" : "Show password"}
                                >
                                    {showConfirmPassword ? <EyeSlashIcon className="h-5 w-5" /> : <EyeIcon className="h-5 w-5" />}
                                </button>
                            </div>
                        </div>
                    </div>
                    <div>
                        <button type="submit" className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary hover:bg-secondary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary">
                            Continue
                        </button>
                    </div>
                </div>
            </form>
             <div className="mt-6">
                <div className="relative">
                    <div className="absolute inset-0 flex items-center">
                        <div className="w-full border-t border-gray-300"></div>
                    </div>
                    <div className="relative flex justify-center text-sm">
                        <span className="px-2 bg-white text-gray-500">Or continue with</span>
                    </div>
                </div>
                <div className="mt-6 grid grid-cols-2 gap-3">
                    <button onClick={() => onSocialClick('google')} className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 hover:text-gray-800 transition-colors"><span className="sr-only">Sign up with Google</span><GoogleIcon /></button>
                    <button onClick={() => onSocialClick('apple')} className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 hover:text-gray-800 transition-colors"><span className="sr-only">Sign up with Apple</span><AppleIcon /></button>
                </div>
            </div>
        </div>
    );
};

const ForgotPasswordTab: React.FC<{ onBack: () => void }> = ({ onBack }) => {
    const [email, setEmail] = useState('');
    const [submitted, setSubmitted] = useState(false);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        // In a real app, you'd call an API to send the reset email.
        console.log(`Password reset requested for: ${email}`);
        setSubmitted(true);
    };

    if (submitted) {
        return (
            <div className="text-center">
                <h3 className="text-xl font-semibold text-dark">Check Your Email</h3>
                <p className="mt-2 text-gray-600">
                    If an account with that email exists, we've sent instructions on how to reset your password.
                </p>
                <button
                    onClick={onBack}
                    className="mt-6 font-medium text-primary hover:text-secondary"
                >
                    &larr; Back to Login
                </button>
            </div>
        );
    }

    return (
        <div>
            <h3 className="text-xl font-semibold text-dark text-center mb-2">Forgot Your Password?</h3>
            <p className="text-sm text-gray-600 text-center mb-6">No worries! Enter your email and we'll send you a reset link.</p>
            <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                    <label htmlFor="reset-email" className="block text-sm font-medium text-gray-700">Email address</label>
                    <input 
                        type="email" 
                        id="reset-email" 
                        autoComplete="email" 
                        required 
                        className="mt-1 block w-full px-3 py-2 border border-gray-600 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-dark text-light" 
                        placeholder="you@example.com"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                    />
                </div>
                <div>
                    <button type="submit" className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary hover:bg-secondary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary">
                        Send Reset Link
                    </button>
                </div>
            </form>
            <div className="text-center mt-6">
                <button onClick={onBack} className="font-medium text-primary hover:text-secondary">
                    &larr; Back to Login
                </button>
            </div>
        </div>
    );
};

export const Auth: React.FC<AuthProps> = ({ initialTab, onNavigate, onLoginAttempt, onSocialAuth, onInitialSignup, authMessage, onAuthMessageDismiss }) => {
    const [activeTab, setActiveTab] = useState<'login' | 'signup'>(initialTab);
    const [loginView, setLoginView] = useState<'form' | 'forgotPassword'>('form');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    
    // State for Social Account Selection Modal
    const [socialProvider, setSocialProvider] = useState<'google' | 'apple' | null>(null);

    useEffect(() => {
        setActiveTab(initialTab);
    }, [initialTab]);

    useEffect(() => {
        if (authMessage) {
            const timer = setTimeout(() => {
                onAuthMessageDismiss();
            }, 5000);
            return () => clearTimeout(timer);
        }
    }, [authMessage, onAuthMessageDismiss]);

    const handleLogin = () => {
        // Fix: Trim email and password to prevent accidental whitespace issues when copying details
        onLoginAttempt(email.trim(), password.trim());
    };

    const handleTabChange = (tab: 'login' | 'signup') => {
        setActiveTab(tab);
        setLoginView('form');
    };

    const handleSocialSelect = (selectedEmail: string, selectedName: string) => {
        if (socialProvider) {
            onSocialAuth(socialProvider, selectedEmail, selectedName, activeTab);
            setSocialProvider(null);
        }
    };

    return (
        <>
            <div className="min-h-full flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 flex-col">
                <div className="max-w-md w-full space-y-4">
                    {authMessage && (
                        <div 
                            className={`p-4 rounded-md shadow ${authMessage.type === 'success' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}
                            role="alert"
                        >
                            <p className="font-bold">{authMessage.type === 'success' ? 'Success' : 'Error'}</p>
                            <p className="text-sm">{authMessage.text}</p>
                        </div>
                    )}
                    <div className="bg-white p-8 sm:p-10 rounded-xl shadow-lg">
                        <div>
                            <h2 className="text-center text-3xl font-extrabold text-dark">
                               {activeTab === 'login' && loginView === 'form' ? 'Sign in to your account' : 
                                activeTab === 'login' && loginView === 'forgotPassword' ? 'Reset your password' :
                                'Create an account'}
                            </h2>
                            {loginView === 'form' && (
                                 <p className="mt-2 text-center text-sm text-gray-600">
                                    {activeTab === 'login' ? 'New to CleanConnect?' : 'Already have an account?'}
                                    {' '}
                                    <button onClick={() => handleTabChange(activeTab === 'login' ? 'signup' : 'login')} className="font-medium text-primary hover:text-secondary">
                                        {activeTab === 'login' ? 'Create an account' : 'Sign in'}
                                    </button>
                                </p>
                            )}
                        </div>
                        
                        {loginView === 'form' ? (
                            activeTab === 'login' ? (
                                <LoginTab 
                                    email={email}
                                    setEmail={setEmail}
                                    password={password}
                                    setPassword={setPassword}
                                    handleLogin={handleLogin}
                                    onSocialClick={setSocialProvider}
                                    onForgotPasswordClick={() => setLoginView('forgotPassword')}
                                />
                            ) : (
                                <SignupTab onInitialSignup={onInitialSignup} onSocialClick={setSocialProvider} />
                            )
                        ) : (
                            <ForgotPasswordTab onBack={() => setLoginView('form')} />
                        )}
                    </div>
                </div>

                {/* DEMO CREDENTIALS HELPER */}
                <div className="max-w-md w-full mt-8 p-4 bg-yellow-50 border border-yellow-200 rounded-lg text-xs text-yellow-800">
                    <p className="font-bold mb-2 text-sm">Demo Admin Logins (Password: 'password')</p>
                    <div className="grid grid-cols-2 gap-2">
                        <div>
                            <span className="font-semibold block">Super Admin:</span>
                            <span className="select-all">super@cleanconnect.ng</span>
                        </div>
                        <div>
                            <span className="font-semibold block">Payment Admin:</span>
                            <span className="select-all">payment@cleanconnect.ng</span>
                        </div>
                        <div>
                            <span className="font-semibold block">Verification Admin:</span>
                            <span className="select-all">verification@cleanconnect.ng</span>
                        </div>
                        <div>
                            <span className="font-semibold block">Support Admin:</span>
                            <span className="select-all">support@cleanconnect.ng</span>
                        </div>
                    </div>
                </div>
            </div>
            
            {socialProvider && (
                <SocialAccountSelectorModal 
                    provider={socialProvider} 
                    onClose={() => setSocialProvider(null)}
                    onSelect={handleSocialSelect}
                />
            )}
        </>
    );
};
