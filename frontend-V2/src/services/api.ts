import { LoginCredentials, RegisterCredentials, SignTransactionData, RequestTransactionData } from '../types';

const API_URL = 'http://localhost:8080';
const BLOCKCHAIN_URL = 'http://localhost:8081';

export const login = async (credentials: LoginCredentials) => {
  const response = await fetch(`${API_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials),
  });
  if (!response.ok) throw new Error('Login failed');
  return response.json();
};

export const register = async (credentials: RegisterCredentials) => {
  const response = await fetch(`${API_URL}/create`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials),
  });
  if (!response.ok) throw new Error('Registration failed');
  return response.json();
};

export const getProfile = async (token: string) => {
  const response = await fetch(`${API_URL}/profile`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });
  if (!response.ok) throw new Error('Failed to fetch profile');
  console.log(response)
  return response.json();
};

export const signTransaction = async (data: SignTransactionData) => {
  const response = await fetch(`${BLOCKCHAIN_URL}/sign`, {
    method: 'GET',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: 'Failed to sign transaction' }));
    throw new Error(errorData.error || 'Failed to sign transaction');
  }
  return response.json();
};

export const requestTransaction = async (data: RequestTransactionData) => {
  const response = await fetch(`${BLOCKCHAIN_URL}/request-txn`, {
    method: 'GET',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: 'Failed to request transaction' }));
    throw new Error(errorData.error || 'Failed to request transaction');
  }
  return response.json();
};