import React, { useState, useEffect } from 'react';
import { User, LoginCredentials, RegisterCredentials, SignTransactionData, RequestTransactionData } from './types';
import { login, register, getProfile, signTransaction, requestTransaction } from './services/api';
import AuthForm from './components/AuthForm';
import Profile from './components/Profile';
import TransactionForms from './components/TransactionForms';

function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (token) {
      fetchProfile();
    }
  }, [token]);

  const fetchProfile = async () => {
    try {
      const userData = await getProfile(token!);
      setUser(userData);
      setError(null);
    } catch (err) {
      setError('Failed to fetch profile');
      handleLogout();
    }
  };

  const handleLogin = async (credentials: LoginCredentials) => {
    try {
      const { token: newToken } = await login(credentials);
      localStorage.setItem('token', newToken);
      setToken(newToken);
      setError(null);
    } catch (err) {
      setError('Login failed. Please check your credentials.');
    }
  };

  const handleRegister = async (credentials: RegisterCredentials) => {
    try {
      await register(credentials);
      await handleLogin({ email: credentials.email, password: credentials.password });
      setError(null);
    } catch (err) {
      setError('Registration failed. Please try again.');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    setError(null);
  };

  const handleSignTransaction = async (data: SignTransactionData) => {
    try {
      await signTransaction(data);
      setError(null);
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to sign transaction');
      return false;
    }
  };

  const handleRequestTransaction = async (data: RequestTransactionData) => {
    try {
      await requestTransaction(data);
      setError(null);
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to request transaction');
      return false;
    }
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <div className="container mx-auto px-4 py-8">
        <div className="flex flex-col items-center space-y-8">
          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative w-full max-w-md">
              <span className="block sm:inline">{error}</span>
            </div>
          )}

          {!token ? (
            <AuthForm onLogin={handleLogin} onRegister={handleRegister} />
          ) : (
            user && (
              <>
                <Profile user={user} onLogout={handleLogout} />
                <TransactionForms
                  did={user.did}
                  onSignTransaction={handleSignTransaction}
                  onRequestTransaction={handleRequestTransaction}
                />
              </>
            )
          )}
        </div>
      </div>
    </div>
  );
}

export default App;