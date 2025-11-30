
import React from 'react';
import { FacebookIcon, TwitterIcon, InstagramIcon, SparklesIcon, YouTubeIcon, TikTokIcon, XIcon } from './icons';
import { View } from '../types';

interface FooterProps {
    onNavigate: (view: View) => void;
}

export const Footer: React.FC<FooterProps> = ({ onNavigate }) => {
    const footerLinks = {
        company: [
            { name: 'About Us', view: 'about' as View },
            { name: 'Services', view: 'servicesPage' as View },
        ],
        support: [
            { name: 'Help Center', view: 'help' as View },
            { name: 'Contact Us', view: 'contact' as View },
        ],
        legal: [
            { name: 'Terms of Service', view: 'terms' as View },
            { name: 'Privacy Policy', view: 'privacy' as View },
        ],
    };

    return (
        <footer className="bg-white border-t mt-auto">
            <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-12">
                <div className="grid grid-cols-2 md:grid-cols-5 gap-8">
                    <div className="col-span-2 md:col-span-2">
                         <div className="flex items-center gap-2 text-2xl font-bold text-primary">
                            <SparklesIcon className="w-8 h-8" />
                            <span>CleanConnect</span>
                        </div>
                        <p className="mt-2 text-gray-500 max-w-xs">
                            Connecting Nigeria with trusted, professional cleaners for a spotless space, every time.
                        </p>
                    </div>
                    <div>
                        <h3 className="text-sm font-semibold text-dark tracking-wider uppercase">Company</h3>
                        <ul className="mt-4 space-y-2">
                            {footerLinks.company.map((item) => (
                                <li key={item.name}>
                                    <button onClick={() => onNavigate(item.view)} className="text-base text-gray-500 hover:text-primary">
                                        {item.name}
                                    </button>
                                </li>
                            ))}
                        </ul>
                    </div>
                    <div>
                        <h3 className="text-sm font-semibold text-dark tracking-wider uppercase">Support</h3>
                        <ul className="mt-4 space-y-2">
                            {footerLinks.support.map((item) => (
                                <li key={item.name}>
                                    <button onClick={() => onNavigate(item.view)} className="text-base text-gray-500 hover:text-primary">
                                        {item.name}
                                    </button>
                                </li>
                            ))}
                        </ul>
                    </div>
                    <div>
                        <h3 className="text-sm font-semibold text-dark tracking-wider uppercase">Legal</h3>
                        <ul className="mt-4 space-y-2">
                            {footerLinks.legal.map((item) => (
                                <li key={item.name}>
                                    <button onClick={() => onNavigate(item.view)} className="text-base text-gray-500 hover:text-primary">
                                        {item.name}
                                    </button>
                                </li>
                            ))}
                        </ul>
                    </div>
                </div>

                <div className="mt-12 border-t pt-8 flex flex-col sm:flex-row justify-between items-center">
                    <p className="text-sm text-gray-500">&copy; {new Date().getFullYear()} CleanConnect. All rights reserved.</p>
                    <div className="flex space-x-6 mt-4 sm:mt-0">
                       <a href="https://facebook.com" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-primary transition-colors">
                           <span className="sr-only">Facebook</span>
                           <FacebookIcon className="h-6 w-6" />
                       </a>
                       <a href="https://instagram.com" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-primary transition-colors">
                           <span className="sr-only">Instagram</span>
                           <InstagramIcon className="h-6 w-6" />
                       </a>
                       <a href="https://twitter.com" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-primary transition-colors">
                           <span className="sr-only">Twitter</span>
                           <TwitterIcon className="h-6 w-6" />
                       </a>
                        <a href="https://x.com" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-primary transition-colors">
                           <span className="sr-only">X</span>
                           <XIcon className="h-6 w-6" />
                       </a>
                       <a href="https://youtube.com" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-primary transition-colors">
                           <span className="sr-only">YouTube</span>
                           <YouTubeIcon className="h-6 w-6" />
                       </a>
                       <a href="https://tiktok.com" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-primary transition-colors">
                           <span className="sr-only">TikTok</span>
                           <TikTokIcon className="h-6 w-6" />
                       </a>
                    </div>
                </div>
            </div>
        </footer>
    );
};
