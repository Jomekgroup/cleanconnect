import React, { useState } from 'react';
import { Booking, Review } from '../types';
import { XCircleIcon, StarIcon } from './icons';

interface ReviewModalProps {
    booking: Booking;
    onClose: () => void;
    onSubmit: (reviewData: Omit<Review, 'reviewerName'>) => void;
}

const RatingInput: React.FC<{ label: string, rating: number, setRating: (r: number) => void }> = ({ label, rating, setRating }) => {
    const [hoverRating, setHoverRating] = useState(0);
    return (
        <div>
            <label className="block text-sm font-medium text-gray-700">{label}</label>
            <div className="mt-1 flex items-center">
                {[1, 2, 3, 4, 5].map((star) => (
                    <div
                        key={star}
                        onClick={() => setRating(star)}
                        onMouseEnter={() => setHoverRating(star)}
                        onMouseLeave={() => setHoverRating(0)}
                    >
                        <StarIcon
                            className={`w-8 h-8 cursor-pointer transition-colors ${
                                (hoverRating || rating) >= star ? 'text-yellow-400' : 'text-gray-300'
                            }`}
                        />
                    </div>
                ))}
            </div>
        </div>
    );
};

export const ReviewModal: React.FC<ReviewModalProps> = ({ booking, onClose, onSubmit }) => {
    const [timeliness, setTimeliness] = useState(0);
    const [thoroughness, setThoroughness] = useState(0);
    const [conduct, setConduct] = useState(0);
    const [comment, setComment] = useState('');

    const handleSubmit = () => {
        if (timeliness === 0 || thoroughness === 0 || conduct === 0) {
            alert("Please provide a rating for all criteria.");
            return;
        }
        const averageRating = (timeliness + thoroughness + conduct) / 3;
        onSubmit({
            rating: parseFloat(averageRating.toFixed(1)),
            timeliness,
            thoroughness,
            conduct,
            comment,
        });
    };
    
    const isFormValid = timeliness > 0 && thoroughness > 0 && conduct > 0;

    return (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4" aria-modal="true" role="dialog">
            <div className="bg-white rounded-2xl shadow-xl w-full max-w-md transform transition-all">
                <div className="p-6 relative">
                    <button onClick={onClose} className="absolute top-4 right-4 text-gray-400 hover:text-gray-600">
                        <XCircleIcon className="w-6 h-6" />
                    </button>

                    <div className="text-center">
                        <h3 className="text-xl font-bold text-gray-900">Leave a Review</h3>
                        <p className="mt-2 text-sm text-gray-500">
                            Share your experience with <span className="font-bold">{booking.cleanerName}</span> for the <span className="font-bold">{booking.service}</span> on <span className="font-bold">{booking.date}</span>.
                        </p>
                    </div>

                    <div className="mt-6 space-y-4">
                        <RatingInput label="Timeliness" rating={timeliness} setRating={setTimeliness} />
                        <RatingInput label="Thoroughness" rating={thoroughness} setRating={setThoroughness} />
                        <RatingInput label="Conduct" rating={conduct} setRating={setConduct} />
                    </div>
                    
                    <div className="mt-6">
                         <label htmlFor="comment" className="block text-sm font-medium text-gray-700">
                            Your Comment (Optional)
                        </label>
                        <textarea
                            id="comment"
                            rows={4}
                            value={comment}
                            onChange={(e) => setComment(e.target.value)}
                            maxLength={500}
                            className="mt-1 block w-full rounded-md border-gray-600 shadow-sm focus:border-primary focus:ring-primary sm:text-sm bg-dark text-light placeholder-gray-400"
                            placeholder="Tell us more about your experience..."
                        ></textarea>
                    </div>

                    <div className="mt-6 flex justify-end gap-4">
                        <button
                            onClick={onClose}
                            type="button"
                            className="rounded-md bg-white px-4 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50"
                        >
                            Cancel
                        </button>
                        <button
                            onClick={handleSubmit}
                            type="button"
                            disabled={!isFormValid}
                            className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-secondary disabled:bg-gray-400"
                        >
                            Submit Review
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};