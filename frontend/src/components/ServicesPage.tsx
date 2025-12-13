import React from 'react';

export const ServicesPage: React.FC = () => {
    // Categorize services for better presentation
    const residentialServices = ["Residential/Domestic Cleaning", "Deep Cleaning", "Move-In / Move-Out Cleaning", "Carpet and Upholstery Cleaning", "Laundry & ironing", "Spring Cleaning", "Green/Eco-Friendly"];
    const commercialServices = ["Commercial/Office Cleaning", "Post-Construction", "Industrial Cleaning", "Glass Cleaning", "Event Cleaning"];
    const specializedServices = ["Medical Cleaning", "Sanitization/Disinfection", "Disaster Cleaning & Restoration", "Hazardous Waste Cleaning", "Crisis/Trauma Cleaning", "Vehicle Cleaning", "Outdoor/Environmental Cleaning", "Pest control", "Waste Management"];

    const renderServiceList = (title: string, services: string[]) => (
        <div className="mb-8">
            <h2 className="text-2xl font-semibold text-primary mb-4">{title}</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                {services.map(service => (
                    <div key={service} className="bg-light p-4 rounded-lg">
                        <p className="font-medium text-dark">{service}</p>
                    </div>
                ))}
            </div>
        </div>
    );

    return (
        <div className="bg-white py-12 px-4 sm:px-6 lg:px-8">
            <div className="container mx-auto">
                <div className="max-w-4xl mx-auto">
                    <h1 className="text-4xl font-bold text-center text-dark mb-4">Our Services</h1>
                    <p className="text-lg text-gray-600 text-center mb-10">
                        We offer a comprehensive range of cleaning services to meet every need. Our professionals are equipped to handle any job, big or small.
                    </p>
                    
                    {renderServiceList("Residential Cleaning", residentialServices)}
                    {renderServiceList("Commercial Cleaning", commercialServices)}
                    {renderServiceList("Specialized Cleaning", specializedServices)}
                </div>
            </div>
        </div>
    );
};
