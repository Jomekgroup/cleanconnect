import React from 'react';
import { SUBSCRIPTION_PLANS } from '../constants/subscriptions';
import { CheckIcon } from './icons';
import { SubscriptionPlan } from '../types';

interface SubscriptionPageProps {
    currentPlan: 'Free' | 'Standard' | 'Pro' | 'Premium';
    onSelectPlan: (plan: SubscriptionPlan) => void;
}

export const SubscriptionPage: React.FC<SubscriptionPageProps> = ({ currentPlan, onSelectPlan }) => {

    return (
        <div className="bg-white py-12 sm:py-24">
            <div className="mx-auto max-w-7xl px-6 lg:px-8">
                <div className="mx-auto max-w-4xl text-center">
                    <h2 className="text-base font-semibold leading-7 text-primary">Pricing</h2>
                    <p className="mt-2 text-4xl font-bold tracking-tight text-gray-900 sm:text-5xl">
                        Plans for every stage of your business
                    </p>
                </div>
                <p className="mx-auto mt-6 max-w-2xl text-center text-lg leading-8 text-gray-600">
                    Choose the plan that's right for you and unlock new features to grow your client base on CleanConnect.
                </p>

                <div className="isolate mx-auto mt-16 grid max-w-md grid-cols-1 gap-8 md:max-w-none md:grid-cols-2 lg:grid-cols-4">
                    {SUBSCRIPTION_PLANS.map((plan) => (
                        <div
                            key={plan.name}
                            className={`rounded-3xl p-8 ring-1 flex flex-col ${plan.isRecommended ? 'ring-2 ring-primary' : 'ring-gray-200'}`}
                        >
                            <h3 className="text-lg font-semibold leading-8 text-gray-900">{plan.name}</h3>
                            <p className="mt-4 text-sm leading-6 text-gray-600">
                                {
                                    plan.name === 'Free' ? 'For those just starting out.' :
                                    plan.name === 'Standard' ? 'For professionals building their client base.' :
                                    plan.name === 'Pro' ? 'For established businesses ready to scale.' :
                                    'For top-tier companies requiring maximum visibility.'
                                }
                            </p>
                             <p className="mt-6 flex items-baseline gap-x-1">
                                <span className="text-4xl font-bold tracking-tight text-gray-900">
                                    ₦{plan.priceMonthly.toLocaleString()}
                                </span>
                                <span className="text-sm font-semibold leading-6 text-gray-600">
                                    /month
                                </span>
                            </p>
                            <ul role="list" className="mt-8 space-y-3 text-sm leading-6 text-gray-600 flex-grow">
                                {plan.features.map((feature) => (
                                    <li key={feature} className="flex gap-x-3">
                                        <CheckIcon className="h-6 w-5 flex-none text-primary" aria-hidden="true" />
                                        {feature}
                                    </li>
                                ))}
                            </ul>

                             {/* Yearly Price at the bottom */}
                            <div className="mt-8 pt-4 border-t border-gray-200/80">
                                {plan.priceYearly > 0 ? (
                                    <p className="text-center text-gray-600">
                                        <span className="text-2xl font-bold text-dark">₦{plan.priceYearly.toLocaleString()}</span>
                                        <span className="text-sm"> / year</span>
                                        <span className="block text-xs font-semibold text-secondary">BILLED ANNUALLY</span>
                                    </p>
                                ) : (
                                    <div className="h-[60px] flex items-center justify-center">
                                         <p className="text-center text-lg font-semibold text-gray-600">Always Free</p>
                                    </div>
                                )}
                            </div>

                             <button
                                onClick={() => onSelectPlan(plan)}
                                disabled={currentPlan === plan.name}
                                className={`mt-6 block w-full rounded-md px-3 py-2 text-center text-sm font-semibold leading-6 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 
                                ${currentPlan === plan.name 
                                    ? 'bg-gray-400 text-white cursor-not-allowed'
                                    : plan.isRecommended 
                                    ? 'bg-primary text-white shadow-sm hover:bg-secondary focus-visible:outline-primary'
                                    : 'bg-white text-primary ring-1 ring-inset ring-primary hover:bg-green-50'
                                }`}
                            >
                                {currentPlan === plan.name ? 'Current Plan' : `Choose ${plan.name}`}
                            </button>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};