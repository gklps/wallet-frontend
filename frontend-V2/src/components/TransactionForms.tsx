import React, { useState } from 'react';
import { SignTransactionData, RequestTransactionData } from '../types';
import { AlertCircle } from 'lucide-react';

interface TransactionFormsProps {
  did: string;
  onSignTransaction: (data: SignTransactionData) => void;
  onRequestTransaction: (data: RequestTransactionData) => void;
}

export default function TransactionForms({ did, onSignTransaction, onRequestTransaction }: TransactionFormsProps) {
  const [txnData, setTxnData] = useState('');
  const [requestData, setRequestData] = useState({
    port: '',
    receiver: '',
    rbt_amount: 0,
  });
  const [loading, setLoading] = useState({
    sign: false,
    request: false,
  });

  const handleSignSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(prev => ({ ...prev, sign: true }));
    try {
      await onSignTransaction({ did, data: txnData });
      setTxnData(''); // Clear form on success
    } finally {
      setLoading(prev => ({ ...prev, sign: false }));
    }
  };

  const handleRequestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(prev => ({ ...prev, request: true }));
    try {
      await onRequestTransaction({
        did,
        ...requestData,
        rbt_amount: Number(requestData.rbt_amount),
      });
      // Clear form on success
      setRequestData({
        port: '',
        receiver: '',
        rbt_amount: 0,
      });
    } finally {
      setLoading(prev => ({ ...prev, request: false }));
    }
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 w-full max-w-4xl">
      <div className="bg-white shadow-lg rounded-lg p-6">
        <div className="flex items-center gap-2 mb-4">
          <h3 className="text-xl font-bold">Sign Transaction</h3>
          <AlertCircle className="w-5 h-5 text-gray-500" title="Sign a blockchain transaction with your DID" />
        </div>
        <form onSubmit={handleSignSubmit}>
          <div className="mb-4">
            <label className="block text-gray-700 text-sm font-bold mb-2">
              Transaction Data
            </label>
            <textarea
              className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
              rows={4}
              value={txnData}
              onChange={(e) => setTxnData(e.target.value)}
              placeholder="Enter transaction data..."
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading.sign || !txnData.trim()}
            className="bg-green-500 hover:bg-green-700 disabled:bg-green-300 disabled:cursor-not-allowed text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full transition-colors"
          >
            {loading.sign ? 'Signing...' : 'Sign Transaction'}
          </button>
        </form>
      </div>

      <div className="bg-white shadow-lg rounded-lg p-6">
        <div className="flex items-center gap-2 mb-4">
          <h3 className="text-xl font-bold">Request Transaction</h3>
          <AlertCircle className="w-5 h-5 text-gray-500" title="Request a new blockchain transaction" />
        </div>
        <form onSubmit={handleRequestSubmit}>
          <div className="mb-4">
            <label className="block text-gray-700 text-sm font-bold mb-2">
              Port Number
            </label>
            <input
              type="text"
              className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
              value={requestData.port}
              onChange={(e) => setRequestData({ ...requestData, port: e.target.value })}
              placeholder="Enter port number..."
              required
              pattern="[0-9]*"
            />
          </div>
          
          <div className="mb-4">
            <label className="block text-gray-700 text-sm font-bold mb-2">
              Receiver DID
            </label>
            <input
              type="text"
              className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline font-mono text-sm"
              value={requestData.receiver}
              onChange={(e) => setRequestData({ ...requestData, receiver: e.target.value })}
              placeholder="Enter receiver DID..."
              required
            />
          </div>

          <div className="mb-4">
            <label className="block text-gray-700 text-sm font-bold mb-2">
              Amount (RBT)
            </label>
            <input
              type="number"
              step="0.000001"
              min="0"
              className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
              value={requestData.rbt_amount}
              onChange={(e) => setRequestData({ ...requestData, rbt_amount: parseFloat(e.target.value) || 0 })}
              placeholder="Enter amount..."
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading.request || !requestData.port || !requestData.receiver || requestData.rbt_amount <= 0}
            className="bg-blue-500 hover:bg-blue-700 disabled:bg-blue-300 disabled:cursor-not-allowed text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full transition-colors"
          >
            {loading.request ? 'Requesting...' : 'Request Transaction'}
          </button>
        </form>
      </div>
    </div>
  );
}