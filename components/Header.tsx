import React from 'react';
import { User, View } from '../types';
import { SparklesIcon } from './icons';

interface HeaderProps {
  user: User | null;
  onNavigate: (view: View) => void;
  onNavigateToAuth: (tab: 'login' | 'signup') => void;
  onLogout: () => void;
}

export const Header: React.FC<HeaderProps> = ({ user, onNavigate, onLogout, onNavigateToAuth }) => {
  return (
    <header className="bg-white/80 backdrop-blur-md shadow-sm sticky top-0 z-50">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center py-4">
          <div 
            className="flex items-center gap-2 text-2xl font-bold text-primary cursor-pointer"
            onClick={() => onNavigate('landing')}
          >
            <SparklesIcon className="w-8 h-8" />
            <span>CleanConnect</span>
          </div>
          <div className="flex items-center space-x-4">
            {user ? (
              <>
                {user.isAdmin && (
                   <button
                    onClick={() => onNavigate('adminDashboard')}
                    className="hidden sm:block text-red-600 hover:text-red-800 font-bold transition-colors"
                  >
                    Admin Dashboard
                  </button>
                )}
                {!user.isAdmin && (
                  <button
                    onClick={() => onNavigate(user.role === 'client' ? 'clientDashboard' : 'cleanerDashboard')}
                    className="hidden sm:block text-gray-700 hover:text-primary font-medium transition-colors"
                  >
                    Dashboard
                  </button>
                )}
                <button
                  onClick={onLogout}
                  className="bg-primary text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-secondary transition-colors"
                >
                  Logout
                </button>
              </>
            ) : (
              <>
                 <button
                    onClick={() => onNavigateToAuth('login')}
                    className="text-gray-700 hover:text-primary font-medium transition-colors"
                  >
                    Login
                  </button>
                  <button
                    onClick={() => onNavigateToAuth('signup')}
                    className="bg-primary text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-secondary transition-colors"
                  >
                    Sign Up
                  </button>
              </>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
