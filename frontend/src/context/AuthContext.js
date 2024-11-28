import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';

// Create a context
const AuthContext = createContext();

// Custom hook to use the AuthContext
export const useAuth = () => useContext(AuthContext);

// AuthProvider component to provide context values
export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token') || null); // Read token from localStorage if present

  // Set the user from token (if token exists)
  useEffect(() => {
    if (token) {
      axios.defaults.headers['Authorization'] = `Bearer ${token}`; // Set default Authorization header globally
      // Make a request to get user details based on token
      axios.get('http://localhost:8080/profile')
        .then((response) => setUser(response.data))
        .catch(() => logout()); // Logout if token is invalid
    }
  }, [token]);

  // Login function
  const login = (newToken, userDetails) => {
    console.log('Logging in with token:', newToken); // Log the token
    setToken(newToken);
    setUser(userDetails);
    localStorage.setItem('token', newToken); // Store token in localStorage
    console.log(localStorage.getItem('token'))
  };

  // Logout function
  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token'); // Remove token from localStorage
  };

  return (
    <AuthContext.Provider value={{ user, token, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};
