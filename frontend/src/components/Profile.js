import React, { useEffect, useState } from "react";
import { Container, Button, Alert } from "react-bootstrap";
import { useAuth } from "../context/AuthContext";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const Profile = () => {
  const { user, token } = useAuth(); // Get user and token from context
  const [profileData, setProfileData] = useState(null);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (token) {
      // Fetch profile data with Authorization header
      axios
        .get("http://localhost:8080/profile", {
          headers: {
            Authorization: `Bearer ${token}` // Pass the token in the Authorization header
          }
        })
        .then((response) => {
          setProfileData(response.data); // Store the profile data in state
        })
        .catch((error) => {
          // Handle errors, for example invalid token
          if (error.response && error.response.data.error) {
            setError(error.response.data.error);
            // Optionally redirect to login if token is invalid
            if (error.response.data.error === "Invalid token") {
              navigate("/login");
            }
          } else {
            setError("An error occurred. Please try again later.");
          }
        });
    }
  }, [token, navigate]); // Re-fetch profile data when token changes

  if (!user || !profileData) {
    return <div>Loading...</div>; // Show loading state
  }

  return (
    <Container className="mt-5">
      <h2>Profile</h2>

      {error && <Alert variant="danger">{error}</Alert>} {/* Show error message if any */}

      <p><strong>Email:</strong> {profileData.email}</p>
      <p><strong>Name:</strong> {profileData.name}</p>

      <Button variant="outline-danger" onClick={() => alert("Feature coming soon!")}>
        Edit
      </Button>
    </Container>
  );
};

export default Profile;
