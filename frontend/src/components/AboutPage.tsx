import React from 'react';

export const AboutPage: React.FC = () => {
    return (
        <div className="bg-white py-12 px-4 sm:px-6 lg:px-8">
            <div className="container mx-auto">
                <div className="max-w-3xl mx-auto">
                    <h1 className="text-4xl font-bold text-center text-dark mb-4">About CleanConnect</h1>
                    <p className="text-lg text-gray-600 text-center mb-8">
                        Connecting Nigeria with trusted, professional cleaners for a spotless space, every time.
                    </p>
                    
                    <div className="space-y-6 text-gray-700">
                        <h2 className="text-2xl font-semibold text-primary">Our Mission</h2>
                        <p>
                            To empower cleaning professionals across Nigeria by providing them with a platform to connect with clients, grow their businesses, and build a reputation for excellence. For clients, our mission is to make finding reliable, vetted, and top-quality cleaning services as simple and seamless as possible.
                        </p>

                        <h2 className="text-2xl font-semibold text-primary">Our Vision</h2>
                        <p>
                            To be the most trusted and widely used platform for cleaning services in Nigeria, setting a new standard for quality, reliability, and professionalism in the industry. We envision a future where every home and business can easily access the best cleaning services, contributing to healthier and more productive environments nationwide.
                        </p>

                        <h2 className="text-2xl font-semibold text-primary">Our Values</h2>
                        <ul className="list-disc list-inside space-y-2">
                            <li><strong>Trust & Safety:</strong> We prioritize the safety and security of our users. All cleaners on our platform undergo a vetting process to ensure they are reliable and trustworthy.</li>
                            <li><strong>Quality:</strong> We are committed to high standards. We encourage continuous feedback and ratings to maintain a community of top-performing professionals.</li>
                            <li><strong>Empowerment:</strong> We provide cleaners with the tools and visibility they need to succeed and build sustainable businesses.</li>
                            <li><strong>Convenience:</strong> Our platform is designed to be user-friendly, making the process of booking and managing cleaning services effortless for clients.</li>
                            <li><strong>Community:</strong> We are building a community of clients and cleaners based on respect, professionalism, and a shared goal of creating clean and happy spaces.</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    );
};
