import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { Form, Button, Container, Alert } from "react-bootstrap";
import { useAuth } from "../context/AuthContext";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const LoginForm = () => {
  const { register, handleSubmit, formState: { errors } } = useForm();
  const { login } = useAuth();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(""); // To hold error messages

  const onSubmit = async (data) => {
    setLoading(true);
    setError(""); // Reset any previous error messages
    try {
      const response = await axios.post("http://localhost:8080/login", {
        email: data.email,
        password: data.password,
      });

      const token = response.data.token;
      login(token, response.data.user);  // Assuming you store user info on success
      navigate("/profile");  // Navigate to the profile page on success
    } catch (error) {
      console.error("Login failed", error);
      if (error.response && error.response.data.error) {
        setError(error.response.data.error); // Show the error message from the backend
      } else {
        setError("An error occurred. Please try again later.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container className="mt-5">
      <h2>Login</h2>

      {/* Show error message if login fails */}
      {error && <Alert variant="danger">{error}</Alert>}

      <Form onSubmit={handleSubmit(onSubmit)}>
        <Form.Group>
          <Form.Label>Email</Form.Label>
          <Form.Control
            type="email"
            {...register("email", { required: "Email is required" })}
            isInvalid={errors.email}
          />
          <Form.Control.Feedback type="invalid">
            {errors.email?.message}
          </Form.Control.Feedback>
        </Form.Group>

        <Form.Group className="mt-3">
          <Form.Label>Password</Form.Label>
          <Form.Control
            type="password"
            {...register("password", { required: "Password is required" })}
            isInvalid={errors.password}
          />
          <Form.Control.Feedback type="invalid">
            {errors.password?.message}
          </Form.Control.Feedback>
        </Form.Group>

        <Button type="submit" variant="primary" disabled={loading} className="mt-3">
          {loading ? "Logging In..." : "Login"}
        </Button>
      </Form>
    </Container>
  );
};

export default LoginForm;
