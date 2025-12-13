
import React, { useState, useEffect } from 'react';
import { SupportTicket, TicketCategory } from '../types';
import { apiService } from '../services/apiService';
import { LifebuoyIcon, ChevronDownIcon } from './icons';

interface SupportTicketSectionProps {
    userId: string;
}

export const SupportTicketSection: React.FC<SupportTicketSectionProps> = ({ userId }) => {
    const [view, setView] = useState<'list' | 'create'>('list');
    const [tickets, setTickets] = useState<SupportTicket[]>([]);
    const [loading, setLoading] = useState(true);
    const [expandedTicketId, setExpandedTicketId] = useState<string | null>(null);

    // Form State
    const [category, setCategory] = useState<TicketCategory | ''>('');
    const [subject, setSubject] = useState('');
    const [message, setMessage] = useState('');
    const [submitting, setSubmitting] = useState(false);

    useEffect(() => {
        loadTickets();
    }, []);

    const loadTickets = async () => {
        setLoading(true);
        try {
            const data = await apiService.getUserTickets();
            setTickets(data);
        } catch (error) {
            console.error("Failed to load tickets", error);
        } finally {
            setLoading(false);
        }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!category || !subject || !message) return;

        setSubmitting(true);
        try {
            await apiService.createSupportTicket({ category, subject, message });
            alert("Ticket submitted successfully! An admin will review it shortly.");
            setCategory('');
            setSubject('');
            setMessage('');
            setView('list');
            loadTickets();
        } catch (error) {
            alert("Failed to submit ticket.");
        } finally {
            setSubmitting(false);
        }
    };

    const categories: TicketCategory[] = ['Technical Issue', 'Payment Issue', 'Booking Dispute', 'Account Verification', 'Other'];

    return (
        <div className="bg-white p-6 rounded-lg shadow-md min-h-[500px]">
            <div className="flex justify-between items-center mb-6">
                <h2 className="text-2xl font-bold text-dark flex items-center gap-2">
                    <LifebuoyIcon className="w-6 h-6 text-primary" />
                    Support & Help
                </h2>
                {view === 'list' ? (
                    <button 
                        onClick={() => setView('create')} 
                        className="bg-primary text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-secondary"
                    >
                        + Open New Ticket
                    </button>
                ) : (
                    <button 
                        onClick={() => setView('list')} 
                        className="text-gray-600 hover:text-dark text-sm font-medium"
                    >
                        &larr; Back to Tickets
                    </button>
                )}
            </div>

            {view === 'list' && (
                <div>
                    {loading ? (
                        <div className="text-center py-10 text-gray-500">Loading your tickets...</div>
                    ) : tickets.length === 0 ? (
                        <div className="text-center py-12 bg-gray-50 rounded-lg">
                            <LifebuoyIcon className="w-12 h-12 text-gray-300 mx-auto mb-3" />
                            <h3 className="text-lg font-medium text-gray-900">No support tickets yet</h3>
                            <p className="text-gray-500 mt-1 mb-4">Need help? Create a ticket to get in touch with our admin team.</p>
                            <button 
                                onClick={() => setView('create')} 
                                className="text-primary font-semibold hover:underline"
                            >
                                Create your first ticket
                            </button>
                        </div>
                    ) : (
                        <div className="space-y-4">
                            {tickets.map((ticket) => (
                                <div key={ticket.id} className="border border-gray-200 rounded-lg overflow-hidden">
                                    <div 
                                        onClick={() => setExpandedTicketId(expandedTicketId === ticket.id ? null : ticket.id)}
                                        className="p-4 bg-gray-50 flex justify-between items-center cursor-pointer hover:bg-gray-100 transition-colors"
                                    >
                                        <div>
                                            <h4 className="font-semibold text-gray-900">{ticket.subject}</h4>
                                            <p className="text-xs text-gray-500 mt-1">
                                                {ticket.category} • {new Date(ticket.createdAt).toLocaleDateString()}
                                            </p>
                                        </div>
                                        <div className="flex items-center gap-3">
                                            <span className={`px-2 py-1 text-xs font-bold rounded-full ${
                                                ticket.status === 'Resolved' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
                                            }`}>
                                                {ticket.status}
                                            </span>
                                            <ChevronDownIcon className={`w-4 h-4 text-gray-400 transform transition-transform ${expandedTicketId === ticket.id ? 'rotate-180' : ''}`} />
                                        </div>
                                    </div>
                                    
                                    {expandedTicketId === ticket.id && (
                                        <div className="p-4 bg-white border-t border-gray-200">
                                            <p className="text-gray-700 mb-4 whitespace-pre-wrap">{ticket.message}</p>
                                            
                                            {ticket.adminResponse && (
                                                <div className="bg-blue-50 p-4 rounded-md border border-blue-100">
                                                    <p className="text-xs font-bold text-blue-800 uppercase mb-1">Admin Response</p>
                                                    <p className="text-gray-800">{ticket.adminResponse}</p>
                                                    <p className="text-xs text-gray-500 mt-2 text-right">
                                                        {ticket.updatedAt && new Date(ticket.updatedAt).toLocaleString()}
                                                    </p>
                                                </div>
                                            )}
                                            
                                            {!ticket.adminResponse && (
                                                <p className="text-xs text-gray-400 italic">Waiting for an admin to respond...</p>
                                            )}
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {view === 'create' && (
                <div className="max-w-xl mx-auto">
                    <h3 className="text-lg font-bold mb-4">Tell us about your issue</h3>
                    <form onSubmit={handleSubmit} className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium text-gray-700">Issue Category</label>
                            <select 
                                value={category} 
                                onChange={(e) => setCategory(e.target.value as TicketCategory)} 
                                required
                                className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-primary focus:border-primary sm:text-sm rounded-md border"
                            >
                                <option value="" disabled>Select a category...</option>
                                {categories.map(c => <option key={c} value={c}>{c}</option>)}
                            </select>
                        </div>
                        
                        <div>
                            <label className="block text-sm font-medium text-gray-700">Subject</label>
                            <input 
                                type="text" 
                                value={subject} 
                                onChange={(e) => setSubject(e.target.value)} 
                                required 
                                maxLength={100}
                                className="mt-1 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md p-2 border focus:ring-primary focus:border-primary"
                                placeholder="Brief summary of the issue"
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-700">Description</label>
                            <textarea 
                                value={message} 
                                onChange={(e) => setMessage(e.target.value)} 
                                required 
                                rows={5}
                                className="mt-1 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md p-2 border focus:ring-primary focus:border-primary"
                                placeholder="Please describe your issue in detail..."
                            ></textarea>
                        </div>

                        <div className="pt-4 flex justify-end gap-3">
                            <button 
                                type="button" 
                                onClick={() => setView('list')}
                                className="bg-white py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 hover:bg-gray-50"
                            >
                                Cancel
                            </button>
                            <button 
                                type="submit" 
                                disabled={submitting}
                                className="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-primary hover:bg-secondary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary disabled:opacity-50"
                            >
                                {submitting ? 'Submitting...' : 'Submit Ticket'}
                            </button>
                        </div>
                    </form>
                </div>
            )}
        </div>
    );
};
