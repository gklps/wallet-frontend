import { LoginCredentials, RegisterCredentials, SignTransactionData, RequestTransactionData } from '../types';

const API_URL = 'http://localhost:8080';
const BLOCKCHAIN_URL = 'http://localhost:8081';

const handleEmptyResponse = async (response: Response) => {
  if (!response.ok) {
    if (response.status === 204 || response.statusText === 'No Content') {
      throw new Error('Invalid request parameters or unauthorized operation');
    }
    const text = await response.text();
    throw new Error(text || 'Operation failed');
  }
  const text = await response.text();
  if (!text) {
    throw new Error('Empty response from server');
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error('Invalid response format');
  }
};

export const login = async (credentials: LoginCredentials) => {
  const response = await fetch(`${API_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials),
  });
  return handleEmptyResponse(response);
};

export const register = async (credentials: RegisterCredentials) => {
  const response = await fetch(`${API_URL}/create`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials),
  });
  return handleEmptyResponse(response);
};

export const getProfile = async (token: string) => {
  const response = await fetch(`${API_URL}/profile`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });
  return handleEmptyResponse(response);
};

export const signTransaction = async (data: SignTransactionData) => {
  // Validate DID format
  if (!data.did.startsWith('bafybm')) {
    throw new Error('Invalid DID format. DID must start with "bafybm"');
  }

  const response = await fetch(`${BLOCKCHAIN_URL}/sign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return handleEmptyResponse(response);
};

export const requestTransaction = async (data: RequestTransactionData) => {
  // Validate DID format
  if (!data.did.startsWith('bafybm') || !data.receiver.startsWith('bafybm')) {
    throw new Error('Invalid DID format. Both sender and receiver DIDs must start with "bafybm"');
  }

  // Validate port number
  if (!/^\d{5}$/.test(data.port)) {
    throw new Error('Invalid port number. Must be a 5-digit number');
  }

  // Validate amount (must be positive and have max 3 decimal places)
  if (data.rbt_amount <= 0 || !Number.isFinite(data.rbt_amount)) {
    throw new Error('Invalid amount. Must be a positive number');
  }
  
  const decimalPlaces = (data.rbt_amount.toString().split('.')[1] || '').length;
  if (decimalPlaces > 3) {
    throw new Error('Amount cannot have more than 3 decimal places');
  }

  if (data.rbt_amount < 0.001) {
    throw new Error('Minimum amount is 0.001 RBT');
  }

  const response = await fetch(`${BLOCKCHAIN_URL}/request_txn`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return handleEmptyResponse(response);
};