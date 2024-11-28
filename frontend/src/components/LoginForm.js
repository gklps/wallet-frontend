// src/components/LoginForm.js
import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { Form, Button, Container } from 'react-bootstrap';
import { useAuth } from '../context/AuthContext';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const LoginForm = () => {
  const { register, handleSubmit, formState: { errors } } = useForm();
  const { login } = useAuth();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);

  const onSubmit = async (data) => {
    setLoading(true);
    try {
      const response = await axios.post('http://localhost:8080/login', data);
      const token = response.data.token;
      const userDetails = { email: data.email }; // Customize this based on the response from your backend
      login(token, userDetails);
      navigate('/profile');
    } catch (error) {
      console.error('Login failed', error);
      alert('Login failed! Check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container className="mt-5">
      <h2>Login</h2>
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
        <Form.Group>
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
        <Button type="submit" variant="primary" disabled={loading}>
          {loading ? "Logging In..." : "Login"}
        </Button>
      </Form>
    </Container>
  );
};

export default LoginForm;
