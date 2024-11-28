import React, { useEffect, useState } from 'react';
import { Container, Button } from 'react-bootstrap';
import { useAuth } from '../context/AuthContext';
import axios from 'axios';

const Profile = () => {
  const { token, logout } = useAuth(); // Get user data from AuthContext
  const [profileData, setProfileData] = useState(null);
  const [error, setError] = useState(null); // For error handling
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      console.log('User token:', token); // Log the token to check
      console.log('User is logged in, fetching profile data...');
      // Make an authenticated request to fetch the profile
      axios.get('http://localhost:8080/profile', {
        headers: {
          Authorization: `Bearer ${token}`, // Send token in Authorization header
        },
      })
        .then((response) => {
          setProfileData(response.data); // Set profile data
          setLoading(false); // Stop loading once data is fetched
        })
        .catch((err) => {
          // Enhanced error logging for debugging
          console.error('Failed to fetch profile:', err);
          if (err.response) {
            // If there is a response error from the backend
            console.error('Response error:', err.response.data);
            setError(`Error: ${err.response.data.error || 'Unknown error'}`);
          } else if (err.request) {
            // If the request was made but no response was received
            console.error('Request error:', err.request);
            setError('Network error: No response from server.');
          } else {
            // If something else went wrong
            console.error('General error:', err.message);
            setError('An unexpected error occurred.');
          }
          setLoading(false);
        });
    } else {
      setError('You are not logged in.');
      setLoading(false);
    }
  }, [token]); // Re-run when the `user` object changes

  if (loading) {
    return <div>Loading...</div>; // Show loading message until data is fetched
  }

  if (error) {
    return <div>{error}</div>; // Show error message if any
  }

  return (
    <Container className="mt-5">
      <h2>Profile</h2>
      {profileData ? (
        <>
          <p><strong>Email:</strong> {profileData.email}</p>
          <p><strong>Name:</strong> {profileData.name}</p>
          <p><strong>DID:</strong> {profileData.DID}</p>
          <Button variant="outline-danger" onClick={logout}>Logout</Button>
        </>
      ) : (
        <div>No profile data available</div>
      )}
    </Container>
  );
};

export default Profile;
