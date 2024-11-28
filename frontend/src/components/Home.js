import React from "react";
import { Container } from "react-bootstrap";
import { useAuth } from "../context/AuthContext";

const Home = () => {
  const { user } = useAuth();

  return (
    <Container className="mt-5">
      <h2>Welcome {user ? user.did : "Guest"}</h2>
      <p>This is your Rubix Wallet Home Page</p>
    </Container>
  );
};

export default Home;
