import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';  // Optional: Custom CSS for your app (like global styles)
import App from './App';  // Import your main App component
import { AuthProvider } from './context/AuthContext';  // Auth Context for global state management
import 'bootstrap/dist/css/bootstrap.min.css';  // Import Bootstrap CSS globally

// Render the root of the application inside the "root" div in index.html
ReactDOM.render(
  <AuthProvider>  {/* Provide AuthContext to the entire app */}
    <App />
  </AuthProvider>,
  document.getElementById('root')
);
