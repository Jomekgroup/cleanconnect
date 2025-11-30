import React from 'react';

const FAQItem: React.FC<{ question: string, children: React.ReactNode }> = ({ question, children }) => (
    <details className="p-4 rounded-lg bg-light group">
        <summary className="font-semibold text-dark cursor-pointer list-none flex justify-between items-center">
            {question}
            <span className="transform transition-transform duration-300 group-open:rotate-180">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7"></path></svg>
            </span>
        </summary>
        <div className="mt-4 text-gray-600">
            {children}
        </div>
    </details>
);

export const HelpCenterPage: React.FC = () => {
    return (
        <div className="bg-white py-12 px-4 sm:px-6 lg:px-8">
            <div className="container mx-auto">
                <div className="max-w-3xl mx-auto">
                    <h1 className="text-4xl font-bold text-center text-dark mb-4">Help Center</h1>
                    <p className="text-lg text-gray-600 text-center mb-8">
                        Have questions? We're here to help. Check out our frequently asked questions below.
                    </p>
                    
                    <div className="space-y-4">
                        <h2 className="text-2xl font-semibold text-primary mt-6">For Clients</h2>
                        <FAQItem question="How do I book a cleaner?">
                            <p>Simply use the search bar on our homepage to find cleaners in your area. You can filter by service type and location. Once you find a cleaner you like, click "Book Now" on their profile to start the process.</p>
                        </FAQItem>
                        <FAQItem question="What is the Escrow payment system?">
                            <p>Our Escrow system provides a secure way to pay. You pay CleanConnect, and we hold the funds until you confirm the job has been completed to your satisfaction. This adds a layer of protection for both you and the cleaner. A 10% service fee applies to all Escrow payments.</p>
                        </FAQItem>
                        <FAQItem question="How do I confirm a job is completed?">
                            <p>After a job is done, go to the "My Bookings" tab on your dashboard. You will see a button to "Approve Job Completion" or "Mark as Completed". Clicking this will notify us (for Escrow) or simply update the job status (for direct payments).</p>
                        </FAQItem>

                        <h2 className="text-2xl font-semibold text-primary mt-6">For Cleaners</h2>
                        <FAQItem question="How do I sign up as a cleaner?">
                            <p>Click "Sign Up" on the homepage, then choose "I'm a Cleaner". You'll be guided through a detailed registration process where you'll provide your personal details, professional experience, services offered, and documents for verification.</p>
                        </FAQItem>
                        <FAQItem question="Why do I need to pay for a subscription?">
                            <p>Our subscription plans help you grow your business by giving you access to more clients, higher visibility in search results, and a professional badge on your profile. We have plans for every stage, including a free option to get you started.</p>
                        </FAQItem>
                        <FAQItem question="How do I get paid?">
                            <p>For jobs paid via our Escrow system, the payment will be released to your registered bank account after the client approves the job completion and our admin team processes the payout. For direct payments, you are responsible for arranging payment directly with the client.</p>
                        </FAQItem>
                    </div>
                </div>
            </div>
        </div>
    );
};
