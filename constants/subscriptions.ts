import { SubscriptionPlan } from '../types';

export const SUBSCRIPTION_PLANS: SubscriptionPlan[] = [
    {
        name: 'Free',
        priceMonthly: 0,
        priceYearly: 0,
        features: [
            'Access 1 client per month',
            'Basic profile listing',
            'Standard search visibility',
            'Standard support',
        ],
    },
    {
        name: 'Standard',
        priceMonthly: 5000,
        priceYearly: 50000,
        features: [
            'Access 3 clients per month',
            'Enhanced profile with "STANDARD" badge',
            'Improved search visibility',
            'Email support',
        ],
    },
    {
        name: 'Pro',
        priceMonthly: 15000,
        priceYearly: 150000,
        features: [
            'Access 6 clients per month',
            'Professional profile with "PRO" badge',
            'High search ranking',
            'Priority support',
            'Featured cleaner eligibility',
        ],
        isRecommended: true,
    },
    {
        name: 'Premium',
        priceMonthly: 30000,
        priceYearly: 300000,
        features: [
            'Access 13 clients per month',
            'Premium profile with "PREMIUM" badge',
            'Top search placement',
            'Dedicated 24/7 support',
            'Guaranteed featured placements',
            'Advanced analytics',
        ],
    },
];

export const CLIENT_LIMITS: { [key in 'Free' | 'Standard' | 'Pro' | 'Premium']: number } = {
    Free: 1,
    Standard: 3,
    Pro: 6,
    Premium: 13,
};