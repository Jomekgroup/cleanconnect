import React from 'react';

export const PrivacyPage: React.FC = () => {
    return (
        <div className="bg-white py-12 px-4 sm:px-6 lg:px-8">
            <div className="container mx-auto">
                <div className="max-w-3xl mx-auto prose">
                    <h1 className="text-4xl font-bold text-center text-dark mb-8">Privacy Policy</h1>
                    <p className="text-sm text-gray-500 text-center mb-8">Last updated: {new Date().toLocaleDateString()}</p>

                    <h2>1. Information We Collect</h2>
                    <p>We collect information you provide directly to us, such as when you create an account, including your name, email, phone number, address, and payment information. We also collect information about your use of our services, such as booking history.</p>

                    <h2>2. How We Use Your Information</h2>
                    <p>We use your information to operate, maintain, and provide the features of the CleanConnect platform. This includes connecting Clients with Cleaners, processing payments, and communicating with you.</p>

                    <h2>3. Information Sharing</h2>
                    <p>We may share necessary information between a Client and a Cleaner to facilitate a booking. We do not sell your personal data to third parties. We may share information with law enforcement if required by law.</p>

                    <h2>4. Data Security</h2>
                    <p>We implement reasonable security measures to protect your information from unauthorized access, alteration, or disclosure.</p>

                    <h2>5. Your Choices</h2>
                    <p>You can review and update your account information at any time by logging into your account dashboard.</p>
                </div>
            </div>
        </div>
    );
};
