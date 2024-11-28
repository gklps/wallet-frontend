import React, { createContext, useState, useContext, useEffect } from "react";

// Create a Context for Authentication
const AuthContext = createContext();

// AuthProvider component to wrap around the app and provide state
export const AuthProvider = ({ children }) => {
  // Use localStorage to persist token and user across page reloads
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem("token") || null);

  // Check if token exists on initial load (to persist login state)
  useEffect(() => {
    if (token) {
      // You can fetch user data from your API with the token if needed
      // For now, assuming the token is valid, we store it in the state
      // Example: Fetch user info (you can adapt this if needed)
      // axios.get("/profile", { headers: { Authorization: `Bearer ${token}` } })
      //    .then(response => setUser(response.data))
      //    .catch(err => console.error(err)); 
    }
  }, [token]);

  // Login function to set token and user
  const login = (token, user) => {
    setToken(token);
    setUser(user);
    localStorage.setItem("token", token); // Store token in localStorage
  };

  // Logout function to clear token and user
  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem("token"); // Remove token from localStorage
  };

  return (
    <AuthContext.Provider value={{ user, token, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook to use the AuthContext in any component
export const useAuth = () => {
  return useContext(AuthContext);
};
