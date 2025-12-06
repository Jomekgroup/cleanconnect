
import React from 'react';
import { Cleaner } from '../types';
import { StarIcon, MapPinIcon, RocketLaunchIcon, CheckBadgeIcon } from './icons';

interface CleanerCardProps {
  cleaner: Cleaner;
  onClick: () => void;
}

export const CleanerCard: React.FC<CleanerCardProps> = ({ cleaner, onClick }) => {
  const locationString = cleaner.city === 'Other' && cleaner.otherCity ? cleaner.otherCity : cleaner.city;
  return (
    <div
      onClick={onClick}
      className="bg-white rounded-xl shadow-md overflow-hidden transform hover:-translate-y-1 hover:shadow-xl transition-all duration-300 flex flex-col cursor-pointer"
    >
      <div className="relative">
        <img 
            className="h-56 w-full object-cover" 
            src={cleaner.photoUrl} 
            alt={cleaner.name} 
            onError={(e) => { e.currentTarget.src = 'https://via.placeholder.com/400x300?text=No+Image'; }}
        />
        <div className="absolute top-2 right-2 bg-black bg-opacity-50 text-white px-2 py-1 rounded-full text-xs font-semibold flex items-center gap-1">
          <StarIcon className="w-4 h-4 text-yellow-400" />
          <span>{cleaner.rating.toFixed(1)}</span>
        </div>
        {cleaner.subscriptionTier !== 'Free' && (
             <div className={`absolute top-2 left-2 text-white px-2.5 py-1 rounded-full text-xs font-bold flex items-center gap-1 shadow-lg ${
                cleaner.subscriptionTier === 'Premium' ? 'bg-gradient-to-r from-purple-500 to-indigo-600' :
                cleaner.subscriptionTier === 'Pro' ? 'bg-gradient-to-r from-blue-500 to-cyan-500' :
                cleaner.subscriptionTier === 'Standard' ? 'bg-gradient-to-r from-green-500 to-teal-500' : ''
             }`}>
                <RocketLaunchIcon className="w-4 h-4" />
                <span>{cleaner.subscriptionTier.toUpperCase()}</span>
             </div>
        )}
      </div>
      <div className="p-4 flex flex-col flex-grow">
        <div className="flex items-center gap-1.5">
            <h3 className="text-lg font-bold text-dark">{cleaner.name}</h3>
            {cleaner.isVerified && <CheckBadgeIcon className="w-5 h-5 text-secondary" />}
        </div>
        <p className="text-sm text-gray-600 font-medium flex items-center">
            <MapPinIcon className="w-4 h-4 mr-1 text-gray-400" />
            {locationString}, {cleaner.state}
        </p>
         <div className="mt-2">
            {cleaner.chargeHourly ? (
                <>
                    <span className="text-xl font-bold text-primary">
                        ₦{cleaner.chargeHourly.toLocaleString()}
                    </span>
                    <span className="text-xs text-gray-500 ml-1">
                        /hour
                    </span>
                </>
            ) : cleaner.chargeDaily ? (
                <>
                    <span className="text-xl font-bold text-primary">
                        ₦{cleaner.chargeDaily.toLocaleString()}
                    </span>
                    <span className="text-xs text-gray-500 ml-1">
                        /day
                    </span>
                </>
            ) : cleaner.chargePerContract ? (
                 <>
                    <span className="text-xl font-bold text-primary">
                        ₦{cleaner.chargePerContract.toLocaleString()}
                    </span>
                    <span className="text-xs text-gray-500 ml-1">
                        /contract
                    </span>
                </>
            ) : cleaner.chargePerContractNegotiable ? (
                <span className="text-xl font-bold text-primary">Negotiable</span>
            ) : (
                <span className="text-lg font-semibold text-gray-700">Contact for price</span>
            )}
        </div>
        <div className="mt-3">
          {cleaner.serviceTypes.slice(0, 2).map((service) => (
            <span key={service} className="inline-block bg-green-100 text-primary text-xs font-semibold mr-2 px-2.5 py-0.5 rounded-full mb-1">
              {service}
            </span>
          ))}
        </div>
        <div className="mt-auto pt-4">
              <button
                className="w-full bg-primary text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-secondary transition-colors"
              >
                Book Now
              </button>
        </div>
      </div>
    </div>
  );
};
