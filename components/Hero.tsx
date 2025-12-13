
import React, { useState } from 'react';
import { BriefcaseIcon, MapPinIcon, ChevronDownIcon, CreditCardIcon, StarIcon, UserGroupIcon } from './icons';
import { CLEANING_SERVICES } from '../constants/services';

interface HeroProps {
    onSearch: (filters: { service: string, location: string, minPrice: string, maxPrice: string, minRating: string }) => void;
}

export const Hero: React.FC<HeroProps> = ({ onSearch }) => {
    const [location, setLocation] = useState('');
    const [service, setService] = useState('');
    const [minPrice, setMinPrice] = useState('');
    const [maxPrice, setMaxPrice] = useState('');
    const [minRating, setMinRating] = useState('');
    const [isAdvancedOpen, setIsAdvancedOpen] = useState(false);

    const handleSearch = () => {
        onSearch({ service, location, minPrice, maxPrice, minRating });
    }

    return (
        <div className="relative bg-cover bg-center h-[600px]" style={{ backgroundImage: "url('https://images.unsplash.com/photo-1581578731548-c64695cc6952?q=80&w=2070&auto=format&fit=crop&ixlib-rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D')" }}>
            <div className="absolute inset-0 bg-black/60"></div>
            <div className="relative container mx-auto px-4 sm:px-6 lg:px-8 h-full flex flex-col justify-center items-center text-center text-white">
                <h1 className="text-4xl md:text-5xl lg:text-6xl font-extrabold tracking-tight mb-6">
                    Find Trusted Cleaners Near You
                </h1>
                <p className="text-lg md:text-xl max-w-3xl mx-auto text-gray-200 mb-10">
                    Connect instantly with top-rated professionals for home, office, and specialized cleaning services.
                </p>
                
                {/* Search Box Container */}
                <div className="w-full max-w-4xl bg-white rounded-xl p-2 shadow-2xl">
                    <form onSubmit={(e) => { e.preventDefault(); handleSearch(); }}>
                        <div className="flex flex-col md:flex-row gap-2">
                            {/* Service Input Group */}
                            <div className="flex-1 relative bg-gray-900 rounded-lg px-3 py-1.5 hover:bg-gray-800 transition-colors group focus-within:ring-2 focus-within:ring-primary focus-within:bg-gray-900 border border-transparent focus-within:border-primary/50 cursor-pointer">
                                <label htmlFor="service" className="block text-[9px] font-bold text-gray-400 uppercase tracking-wider mb-0 text-left">Service</label>
                                <div className="flex items-center">
                                    <BriefcaseIcon className="w-4 h-4 text-gray-400 mr-2 group-focus-within:text-primary transition-colors" />
                                    <select 
                                        id="service" 
                                        className="w-full bg-transparent border-none outline-none text-white font-medium text-sm appearance-none focus:ring-0 p-0 cursor-pointer placeholder-gray-500"
                                        value={service}
                                        onChange={(e) => setService(e.target.value)}
                                    >
                                        <option value="" className="text-gray-900">All Services</option>
                                        {CLEANING_SERVICES.map((serviceName) => (
                                            <option key={serviceName} value={serviceName} className="text-gray-900">
                                                {serviceName}
                                            </option>
                                        ))}
                                    </select>
                                    <ChevronDownIcon className="w-3 h-3 text-gray-400 ml-1 pointer-events-none" />
                                </div>
                            </div>

                            {/* Location Input Group */}
                            <div className="flex-1 relative bg-gray-900 rounded-lg px-3 py-1.5 hover:bg-gray-800 transition-colors group focus-within:ring-2 focus-within:ring-primary focus-within:bg-gray-900 border border-transparent focus-within:border-primary/50 cursor-text">
                                <label htmlFor="location" className="block text-[9px] font-bold text-gray-400 uppercase tracking-wider mb-0 text-left">Location</label>
                                <div className="flex items-center">
                                    <MapPinIcon className="w-4 h-4 text-gray-400 mr-2 group-focus-within:text-primary transition-colors" />
                                    <input 
                                        type="text" 
                                        id="location" 
                                        placeholder="City or State" 
                                        className="w-full bg-transparent border-none outline-none text-white font-medium text-sm placeholder-gray-500 focus:ring-0 p-0"
                                        value={location}
                                        onChange={(e) => setLocation(e.target.value)}
                                    />
                                </div>
                            </div>
                            
                            {/* Toggle Advanced Button */}
                             <button
                                type="button"
                                onClick={() => setIsAdvancedOpen(!isAdvancedOpen)}
                                className={`px-4 py-2 rounded-lg font-semibold text-xs sm:text-sm transition-all flex items-center justify-center gap-2 border whitespace-nowrap md:w-auto
                                    ${isAdvancedOpen ? 'bg-gray-200 text-gray-900 border-gray-300' : 'bg-gray-100 text-gray-700 border-transparent hover:bg-gray-200'}`}
                            >
                                <span>{isAdvancedOpen ? 'Less Filters' : 'More Filters'}</span>
                                {isAdvancedOpen ? (
                                    <ChevronDownIcon className="w-3 h-3 text-gray-600 rotate-180 transition-transform" />
                                ) : (
                                     <div className="bg-white rounded-full p-0.5 shadow-sm"><ChevronDownIcon className="w-2.5 h-2.5 text-gray-500" /></div> 
                                )}
                            </button>

                            {/* Search Button */}
                            <button
                                type="submit"
                                className="bg-primary text-white px-6 py-2 rounded-lg text-sm font-bold hover:bg-secondary transition-all shadow-lg active:scale-95 md:w-auto w-full"
                            >
                                Search
                            </button>
                        </div>

                        {/* Collapsible Advanced Filters */}
                        <div className={`overflow-hidden transition-all duration-300 ease-in-out ${isAdvancedOpen ? 'max-h-[500px] opacity-100 mt-2 border-t border-gray-100 pt-2' : 'max-h-0 opacity-0'}`}>
                             <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                                <div className="relative bg-gray-900 rounded-lg px-3 py-1.5 group focus-within:bg-gray-900 focus-within:ring-2 focus-within:ring-primary border border-transparent">
                                    <label className="block text-[9px] font-bold text-gray-400 uppercase tracking-wider mb-0 text-left">Min Price (₦)</label>
                                    <div className="flex items-center">
                                        <CreditCardIcon className="w-4 h-4 text-gray-400 mr-2 group-focus-within:text-primary transition-colors" />
                                        <input 
                                            type="number" 
                                            placeholder="Min" 
                                            className="w-full bg-transparent border-none outline-none text-white text-sm font-medium placeholder-gray-500 focus:ring-0 p-0"
                                            value={minPrice}
                                            onChange={(e) => setMinPrice(e.target.value)}
                                            min="0"
                                        />
                                    </div>
                                </div>

                                <div className="relative bg-gray-900 rounded-lg px-3 py-1.5 group focus-within:bg-gray-900 focus-within:ring-2 focus-within:ring-primary border border-transparent">
                                    <label className="block text-[9px] font-bold text-gray-400 uppercase tracking-wider mb-0 text-left">Max Price (₦)</label>
                                    <div className="flex items-center">
                                        <CreditCardIcon className="w-4 h-4 text-gray-400 mr-2 group-focus-within:text-primary transition-colors" />
                                        <input 
                                            type="number" 
                                            placeholder="Max" 
                                            className="w-full bg-transparent border-none outline-none text-white text-sm font-medium placeholder-gray-500 focus:ring-0 p-0"
                                            value={maxPrice}
                                            onChange={(e) => setMaxPrice(e.target.value)}
                                            min="0"
                                        />
                                    </div>
                                </div>

                                <div className="relative bg-gray-900 rounded-lg px-3 py-1.5 group focus-within:bg-gray-900 focus-within:ring-2 focus-within:ring-primary border border-transparent">
                                    <label className="block text-[9px] font-bold text-gray-400 uppercase tracking-wider mb-0 text-left">Min Rating</label>
                                    <div className="flex items-center">
                                        <StarIcon className="w-4 h-4 text-gray-400 mr-2 group-focus-within:text-primary transition-colors" />
                                        <select 
                                            className="w-full bg-transparent border-none outline-none text-white text-sm font-medium appearance-none focus:ring-0 p-0 cursor-pointer"
                                            value={minRating}
                                            onChange={(e) => setMinRating(e.target.value)}
                                        >
                                            <option value="" className="text-gray-900">Any Rating</option>
                                            <option value="4.5" className="text-gray-900">4.5 & up</option>
                                            <option value="4.0" className="text-gray-900">4.0 & up</option>
                                            <option value="3.0" className="text-gray-900">3.0 & up</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    );
};
