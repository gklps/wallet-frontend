export interface User {
  id: number;
  email: string;
  name: string;
  did: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterCredentials {
  email: string;
  password: string;
  name: string;
}

export interface SignTransactionData {
  did: string;
  data: string;
}

export interface RequestTransactionData {
  port: string;
  did: string;
  receiver: string;
  rbt_amount: number;
}