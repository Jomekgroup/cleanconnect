import React from 'react';

export const TermsPage: React.FC = () => {
    return (
        <div className="bg-white py-12 px-4 sm:px-6 lg:px-8">
            <div className="container mx-auto">
                <div className="max-w-3xl mx-auto prose">
                    <h1 className="text-4xl font-bold text-center text-dark mb-8">Terms of Service</h1>
                    <p className="text-sm text-gray-500 text-center mb-8">Last updated: {new Date().toLocaleDateString()}</p>
                    
                    <h2>1. Introduction</h2>
                    <p>Welcome to CleanConnect. These Terms of Service ("Terms") govern your use of the CleanConnect website and services. By using our platform, you agree to these terms.</p>

                    <h2>2. Services</h2>
                    <p>CleanConnect provides a platform for connecting individuals and companies seeking cleaning services ("Clients") with independent cleaning professionals ("Cleaners"). We are a neutral venue and are not directly involved in the agreements between Clients and Cleaners.</p>

                    <h2>3. User Obligations</h2>
                    <p>You agree to provide accurate and complete information during registration and to keep this information up to date. You are responsible for maintaining the confidentiality of your account password.</p>

                    <h2>4. Payments</h2>
                    <p>For Escrow payments, Clients agree to pay the total amount, including service fees, to CleanConnect. Funds will be released to the Cleaner upon satisfactory completion of the job, as confirmed by the Client. For Direct payments, CleanConnect is not responsible for any disputes, and payment terms are to be agreed upon solely between the Client and the Cleaner.</p>

                    <h2>5. Limitation of Liability</h2>
                    <p>CleanConnect is not liable for any damages arising from the conduct of users on the platform. We are not responsible for the performance or quality of services provided by Cleaners.</p>

                    <h2>6. Termination</h2>
                    <p>We may suspend or terminate your account at our discretion if you violate any of these terms.</p>
                </div>
            </div>
        </div>
    );
};
