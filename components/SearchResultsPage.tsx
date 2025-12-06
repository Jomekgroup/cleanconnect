
import React, { useState, useEffect, useMemo } from 'react';
import { Cleaner } from '../types';
import { MapPinIcon, BriefcaseIcon, ChevronDownIcon, CreditCardIcon, StarIcon, UserGroupIcon } from './icons';
import { CleanerCard } from './CleanerCard';
import { CLEANING_SERVICES } from '../constants/services';

interface SearchResultsPageProps {
    allCleaners: Cleaner[];
    onSelectCleaner: (cleaner: Cleaner) => void;
    initialFilters?: { service: string, location: string, minPrice: string, maxPrice: string, minRating: string } | null;
    clearInitialFilters: () => void;
    appError: string | null;
}

export const SearchResultsPage: React.FC<SearchResultsPageProps> = ({ allCleaners, onSelectCleaner, initialFilters, clearInitialFilters, appError }) => {
    const [activeFilters, setActiveFilters] = useState({ service: '', location: '', minPrice: '', maxPrice: '', minRating: '' });
    const [isAdvancedOpen, setIsAdvancedOpen] = useState(false);

    useEffect(() => {
        if (initialFilters) {
            setActiveFilters(initialFilters);
            // If any advanced filter is set, open the advanced section
            if (initialFilters.minPrice || initialFilters.maxPrice || initialFilters.minRating) {
                setIsAdvancedOpen(true);
            }
            clearInitialFilters();
        }
    }, [initialFilters, clearInitialFilters]);

    const displayedCleaners = useMemo(() => {
        if (appError) return [];

        const { service, location, minPrice, maxPrice, minRating } = activeFilters;

        return allCleaners.filter(cleaner => {
            const serviceMatch = service ? cleaner.serviceTypes.includes(service) : true;
            const locationMatch = location 
                ? cleaner.city.toLowerCase().includes(location.toLowerCase()) || 
                  cleaner.state.toLowerCase().includes(location.toLowerCase()) ||
                  (cleaner.otherCity && cleaner.otherCity.toLowerCase().includes(location.toLowerCase()))
                : true;
            
            let priceMatch = true;
            if (minPrice || maxPrice) {
                const min = Number(minPrice) || 0;
                const max = Number(maxPrice) || Infinity;
                const rates = [cleaner.chargeHourly, cleaner.chargeDaily, cleaner.chargePerContract].filter(r => r !== undefined && r !== null) as number[];
                
                if (rates.length > 0) {
                     priceMatch = rates.some(r => r >= min && r <= max);
                } else {
                    priceMatch = false; 
                }
            }

            let ratingMatch = true;
            if (minRating) {
                ratingMatch = cleaner.rating >= Number(minRating);
            }

            return serviceMatch && locationMatch && priceMatch && ratingMatch;
        });
    }, [activeFilters, allCleaners, appError]);

    const resultsTitle = useMemo(() => {
        if (activeFilters.service || activeFilters.location || activeFilters.minPrice || activeFilters.maxPrice || activeFilters.minRating) return 'Filtered Results';
        return 'All Available Cleaners';
    }, [activeFilters]);


    const handleFilterChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
        const { name, value } = e.target;
        setActiveFilters(prev => ({ ...prev, [name]: value }));
    };

    return (
        <div className="p-4 sm:p-8 container mx-auto">
            <h1 className="text-3xl font-bold text-dark text-center mb-8">Find the Perfect Cleaner</h1>
            
            {/* Search Bar Container */}
            <div className="w-full bg-white rounded-xl p-2 shadow-xl mb-8">
                <form onSubmit={(e) => e.preventDefault()}>
                    <div className="flex flex-col md:flex-row gap-2">
                        {/* Service Input Group */}
                        <div className="flex-1 relative bg-gray-900 rounded-lg px-3 py-1.5 hover:bg-gray-800 transition-colors group focus-within:ring-2 focus-within:ring-primary focus-within:bg-gray-900 border border-transparent focus-within:border-primary/50 cursor-pointer">
                            <label htmlFor="service" className="block text-[9px] font-bold text-gray-400 uppercase tracking-wider mb-0 text-left">Service</label>
                            <div className="flex items-center">
                                <BriefcaseIcon className="w-4 h-4 text-gray-400 mr-2 group-focus-within:text-primary transition-colors" />
                                <select 
                                    id="service" 
                                    name="service"
                                    className="w-full bg-transparent border-none outline-none text-white font-medium text-sm appearance-none focus:ring-0 p-0 cursor-pointer placeholder-gray-500"
                                    value={activeFilters.service}
                                    onChange={handleFilterChange}
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
                                    name="location"
                                    placeholder="City or State" 
                                    className="w-full bg-transparent border-none outline-none text-white font-medium text-sm placeholder-gray-500 focus:ring-0 p-0"
                                    value={activeFilters.location}
                                    onChange={handleFilterChange}
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
                    </div>

                    {/* Collapsible Advanced Filters */}
                    <div className={`overflow-hidden transition-all duration-300 ease-in-out ${isAdvancedOpen ? 'max-h-[500px] opacity-100 mt-2 border-t border-gray-100 pt-2' : 'max-h-0 opacity-0'}`}>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                            {/* Min Price */}
                            <div className="relative bg-gray-900 rounded-lg px-3 py-1.5 group focus-within:bg-gray-900 focus-within:ring-2 focus-within:ring-primary border border-transparent">
                                <label className="block text-[9px] font-bold text-gray-400 uppercase tracking-wider mb-0 text-left">Min Price (₦)</label>
                                <div className="flex items-center">
                                    <CreditCardIcon className="w-4 h-4 text-gray-400 mr-2 group-focus-within:text-primary transition-colors" />
                                    <input 
                                        type="number" 
                                        name="minPrice"
                                        placeholder="Min" 
                                        className="w-full bg-transparent border-none outline-none text-white text-sm font-medium placeholder-gray-500 focus:ring-0 p-0"
                                        value={activeFilters.minPrice}
                                        onChange={handleFilterChange}
                                        min="0"
                                    />
                                </div>
                            </div>

                            {/* Max Price */}
                            <div className="relative bg-gray-900 rounded-lg px-3 py-1.5 group focus-within:bg-gray-900 focus-within:ring-2 focus-within:ring-primary border border-transparent">
                                <label className="block text-[9px] font-bold text-gray-400 uppercase tracking-wider mb-0 text-left">Max Price (₦)</label>
                                <div className="flex items-center">
                                    <CreditCardIcon className="w-4 h-4 text-gray-400 mr-2 group-focus-within:text-primary transition-colors" />
                                    <input 
                                        type="number" 
                                        name="maxPrice"
                                        placeholder="Max" 
                                        className="w-full bg-transparent border-none outline-none text-white text-sm font-medium placeholder-gray-500 focus:ring-0 p-0"
                                        value={activeFilters.maxPrice}
                                        onChange={handleFilterChange}
                                        min="0"
                                    />
                                </div>
                            </div>

                            {/* Min Rating */}
                            <div className="relative bg-gray-900 rounded-lg px-3 py-1.5 group focus-within:bg-gray-900 focus-within:ring-2 focus-within:ring-primary border border-transparent">
                                <label className="block text-[9px] font-bold text-gray-400 uppercase tracking-wider mb-0 text-left">Min Rating</label>
                                <div className="flex items-center">
                                    <StarIcon className="w-4 h-4 text-gray-400 mr-2 group-focus-within:text-primary transition-colors" />
                                    <select 
                                        name="minRating"
                                        className="w-full bg-transparent border-none outline-none text-white text-sm font-medium appearance-none focus:ring-0 p-0 cursor-pointer"
                                        value={activeFilters.minRating}
                                        onChange={handleFilterChange}
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

            <div className="mt-8">
                <h3 className="text-2xl font-bold">{resultsTitle}</h3>
                {appError && (
                    <div className="mt-4 bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg relative text-center" role="alert">
                        <strong className="font-bold">Connection Error! </strong>
                        <span className="block sm:inline">{appError}</span>
                    </div>
                )}
                {displayedCleaners.length > 0 && !appError ? (
                    <div className="mt-4 grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
                        {displayedCleaners.map(cleaner => (<CleanerCard key={cleaner.id} cleaner={cleaner} onClick={() => onSelectCleaner(cleaner)} />))}
                    </div>
                ) : !appError ? (
                    <p className="mt-4 text-gray-500 bg-white p-6 rounded-lg shadow-sm">No cleaners found matching your criteria.</p>
                ) : null }
            </div>
        </div>
    );
};
