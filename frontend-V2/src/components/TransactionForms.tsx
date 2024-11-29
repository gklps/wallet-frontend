import React, { useState } from 'react';
import { SignTransactionData, RequestTransactionData } from '../types';
import { AlertCircle, Info } from 'lucide-react';
import IconWithTitle from './icons/IconWithTitle';

interface TransactionFormsProps {
  did: string;
  onSignTransaction: (data: SignTransactionData) => Promise<boolean>;
  onRequestTransaction: (data: RequestTransactionData) => Promise<boolean>;
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
  const [success, setSuccess] = useState({
    sign: false,
    request: false,
  });

  const handleSignSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(prev => ({ ...prev, sign: true }));
    setSuccess(prev => ({ ...prev, sign: false }));
    try {
      const result = await onSignTransaction({ did, data: txnData });
      if (result) {
        setSuccess(prev => ({ ...prev, sign: true }));
        setTxnData('');
      }
    } finally {
      setLoading(prev => ({ ...prev, sign: false }));
    }
  };

  const handleRequestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(prev => ({ ...prev, request: true }));
    setSuccess(prev => ({ ...prev, request: false }));
    try {
      const result = await onRequestTransaction({
        did,
        ...requestData,
        rbt_amount: Number(parseFloat(requestData.rbt_amount.toString()).toFixed(3)),
      });
      if (result) {
        setSuccess(prev => ({ ...prev, request: true }));
        setRequestData({
          port: '',
          receiver: '',
          rbt_amount: 0,
        });
      }
    } finally {
      setLoading(prev => ({ ...prev, request: false }));
    }
  };

  const handleAmountChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    const numValue = parseFloat(value);
    if (!isNaN(numValue)) {
      // Limit to 3 decimal places
      const formattedValue = parseFloat(numValue.toFixed(3));
      setRequestData(prev => ({ ...prev, rbt_amount: formattedValue }));
    } else {
      setRequestData(prev => ({ ...prev, rbt_amount: 0 }));
    }
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 w-full max-w-4xl">
      <div className="bg-white shadow-lg rounded-lg p-6">
        <div className="flex items-center gap-2 mb-4">
          <h3 className="text-xl font-bold">Sign Transaction</h3>
          <IconWithTitle 
            icon={AlertCircle}
            title="Sign a blockchain transaction with your DID"
            className="text-gray-500 w-5 h-5"
          />
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
          {success.sign && (
            <div className="mb-4 p-2 bg-green-100 text-green-700 rounded flex items-center gap-2">
              <Info className="w-4 h-4" />
              Transaction signed successfully!
            </div>
          )}
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
          <IconWithTitle 
            icon={AlertCircle}
            title="Request a new blockchain transaction"
            className="text-gray-500 w-5 h-5"
          />
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
              placeholder="Enter 5-digit port number..."
              required
              pattern="[0-9]{5}"
              title="Port must be a 5-digit number"
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
              placeholder="Enter receiver DID (starts with bafybm)..."
              required
              pattern="bafybm.*"
              title="DID must start with 'bafybm'"
            />
          </div>

          <div className="mb-4">
            <label className="block text-gray-700 text-sm font-bold mb-2">
              Amount (RBT)
            </label>
            <input
              type="number"
              step="0.001"
              min="0.001"
              className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
              value={requestData.rbt_amount || ''}
              onChange={handleAmountChange}
              placeholder="Minimum 0.001 RBT"
              required
            />
            <p className="mt-1 text-sm text-gray-500">Minimum amount: 0.001 RBT</p>
          </div>

          {success.request && (
            <div className="mb-4 p-2 bg-green-100 text-green-700 rounded flex items-center gap-2">
              <Info className="w-4 h-4" />
              Transaction requested successfully!
            </div>
          )}

          <button
            type="submit"
            disabled={loading.request || !requestData.port || !requestData.receiver || requestData.rbt_amount < 0.001}
            className="bg-blue-500 hover:bg-blue-700 disabled:bg-blue-300 disabled:cursor-not-allowed text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full transition-colors"
          >
            {loading.request ? 'Requesting...' : 'Request Transaction'}
          </button>
        </form>
      </div>
    </div>
  );
}