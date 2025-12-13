import { User } from '../types';
import { apiService } from './apiService';


/**
 * Sends the user's natural language query to the backend server.
 * The server will then securely call the Gemini API to get relevant cleaner IDs.
 * This is a critical security measure to protect the API key.
 * @param query - The user's search query (e.g., "best cleaner in Abuja").
 * @returns A promise that resolves to an array of matching cleaner IDs.
 */
export const getAiPoweredSearchResults = async (query: string): Promise<string[]> => {
  try {
    // The apiService will handle the actual fetch call to our backend
    const result = await apiService.aiSearchCleaners(query);
    
    // Assuming the backend returns a structure like { matchingIds: ["uuid-1", "uuid-2"] }
    if (result.matchingIds && Array.isArray(result.matchingIds)) {
      return result.matchingIds;
    }

    console.warn("AI search from backend returned unexpected format:", result);
    return [];
  } catch (error) {
    console.error("Error fetching AI search results from backend:", error);
    // Fallback to empty array on error
    return [];
  }
};


// The logic for recommending services based on user profile can remain on the frontend
// as it does not involve sensitive keys or heavy computation.
export const getAiRecommendedServices = (user: User): string[] => {
    const recommendations = new Set<string>();

    if (user.clientType === 'Company') {
        recommendations.add("Commercial/Office Cleaning");
        recommendations.add("Post-Construction");
    } else {
        recommendations.add("Residential/Domestic Cleaning");
        recommendations.add("Deep Cleaning");
    }

    const bookingHistoryServices = user.bookingHistory?.map(b => b.service) || [];
    if (bookingHistoryServices.length > 0) {
        if (bookingHistoryServices.includes("Residential/Domestic Cleaning")) {
            recommendations.add("Carpet and Upholstery Cleaning");
        }
         if (bookingHistoryServices.includes("Commercial/Office Cleaning")) {
            recommendations.add("Glass Cleaning");
        }
    } else {
        // For new users, add some common services
        recommendations.add("Carpet and Upholstery Cleaning");
        recommendations.add("Laundry & ironing");
    }

    // Fill up to 4 recommendations with popular services if needed
    const popularServices = ["Deep Cleaning", "Event Cleaning", "Sanitization/Disinfection", "Move-In / Move-Out Cleaning"];
    let i = 0;
    while (recommendations.size < 4 && i < popularServices.length) {
        recommendations.add(popularServices[i]);
        i++;
    }
    
    return Array.from(recommendations).slice(0, 4);
};