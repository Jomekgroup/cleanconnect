
import React, { useState, useEffect, useMemo } from 'react';
import { Hero } from './Hero';
import { CleanerCard } from './CleanerCard';
import { Cleaner, View } from '../types';

interface LandingPageProps {
    cleaners: Cleaner[]; // Receives all cleaners from App.tsx
    onNavigate: (view: View) => void;
    onSelectCleaner: (cleaner: Cleaner) => void;
    onSearch: (filters: { service: string, location: string, minPrice: string, maxPrice: string, minRating: string }) => void;
    appError: string | null;
}

interface FeaturedCleanersSectionProps {
    loading: boolean;
    cleaners: Cleaner[];
    onSelectCleaner: (cleaner: Cleaner) => void;
    appError: string | null;
}

// A local sorting function to determine "featured" cleaners from the full list.
// The backend should ideally provide a dedicated endpoint for this.
const getFeaturedCleaners = (allCleaners: Cleaner[]): Cleaner[] => {
  const tierScores = { Premium: 4, Pro: 3, Standard: 2, Free: 1 };

  const sortedCleaners = [...allCleaners].sort((a, b) => {
    const scoreA =
      (tierScores[a.subscriptionTier] || 0) * 20 +
      a.rating * 10 +
      (a.reviews / 5) +
      (a.isVerified ? 10 : 0);
    const scoreB =
      (tierScores[b.subscriptionTier] || 0) * 20 +
      b.rating * 10 +
      (b.reviews / 5) +
      (b.isVerified ? 10 : 0);
    return scoreB - scoreA;
  });

  return sortedCleaners.slice(0, 4); // Return top 4 cleaners
};


const FeaturedCleanersSection: React.FC<FeaturedCleanersSectionProps> = ({ loading, cleaners, onSelectCleaner, appError }) => (
    <div className="py-16 md:py-24 bg-white">
        <div className="container mx-auto px-4 sm:px-6 lg:px-8">
            <h2 className="text-3xl md:text-4xl font-bold text-center text-dark">Meet Our Top-Rated Cleaners</h2>
            <p className="mt-4 text-lg text-gray-600 text-center max-w-2xl mx-auto">
                Handpicked professionals who are consistently rated the best by our customers for their reliability and attention to detail.
            </p>
             {appError && (
                <div className="mt-8 bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg relative text-center" role="alert">
                    <strong className="font-bold">Connection Error! </strong>
                    <span className="block sm:inline">{appError}</span>
                </div>
            )}
            <div className="mt-12 grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
               {loading && !appError ? (
                   Array.from({ length: 4 }).map((_, index) => (
                       <div key={index} className="bg-gray-200 rounded-xl w-full h-96 animate-pulse"></div>
                   ))
               ) : !appError && cleaners.length > 0 ? (
                   cleaners.map(cleaner => (
                       <CleanerCard 
                           key={cleaner.id} 
                           cleaner={cleaner} 
                           onClick={() => onSelectCleaner(cleaner)} 
                        />
                   ))
               ) : !appError ? (
                 <div className="col-span-full text-center text-gray-500 py-8">
                    No top-rated cleaners available at the moment.
                </div>
               ) : null}
            </div>
        </div>
    </div>
);

export const LandingPage: React.FC<LandingPageProps> = ({ cleaners, onNavigate, onSelectCleaner, onSearch, appError }) => {
    // The loading state is now determined by whether the cleaners prop has been populated and there's no error
    const loading = cleaners.length === 0 && !appError;

    // Use useMemo to calculate featured cleaners only when the main cleaners list changes
    const featuredCleaners = useMemo(() => getFeaturedCleaners(cleaners), [cleaners]);

    return (
        <>
            <Hero onSearch={onSearch} />
            <FeaturedCleanersSection
                loading={loading}
                cleaners={featuredCleaners}
                onSelectCleaner={onSelectCleaner}
                appError={appError}
            />
        </>
    );
};
