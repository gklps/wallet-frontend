import React from 'react';
import { User } from '../types';

interface ProfileProps {
  user: User;
  onLogout: () => void;
}

export default function Profile({ user, onLogout }: ProfileProps) {
  return (
    <div className="bg-white shadow-lg rounded-lg p-6 w-full max-w-md">
      <div className="text-center mb-6">
        <h2 className="text-2xl font-bold text-gray-800">Profile</h2>
      </div>
      
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-600">Name</label>
          <p className="mt-1 text-lg font-semibold">{user.name}</p>
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-600">Email</label>
          <p className="mt-1 text-lg font-semibold">{user.email}</p>
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-600">DID</label>
          <p className="mt-1 text-sm font-mono bg-gray-50 p-2 rounded break-all">{user.did}</p>
        </div>
      </div>

      <button
        onClick={onLogout}
        className="mt-6 w-full bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
      >
        Logout
      </button>
    </div>
  );
}