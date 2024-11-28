import React from "react";
import { useForm } from "react-hook-form";
import { Form, Button, Container, Alert } from "react-bootstrap";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const RegisterForm = () => {
  const { register, handleSubmit, formState: { errors } } = useForm();
  const navigate = useNavigate();
  const [error, setError] = React.useState(""); // State to hold error message
  const [loading, setLoading] = React.useState(false); // State for loading state

  const onSubmit = async (data) => {
    setLoading(true);
    setError(""); // Reset error message on new submission

    try {
      const response = await axios.post("http://localhost:8080/create", {
        email: data.email,
        name: data.name,
        password: data.password
      });
      // On success, navigate to login page
      navigate("/login");
    } catch (error) {
      console.error("Error creating wallet", error);
      if (error.response && error.response.data.error) {
        setError(error.response.data.error); // Display error from backend
      } else {
        setError("An error occurred. Please try again later.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container className="mt-5">
      <h2>Create a New Wallet</h2>

      {/* Show error message if registration fails */}
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
          <Form.Label>Name</Form.Label>
          <Form.Control
            type="text"
            {...register("name", { required: "Name is required" })}
            isInvalid={errors.name}
          />
          <Form.Control.Feedback type="invalid">
            {errors.name?.message}
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
          {loading ? "Creating..." : "Register"}
        </Button>
      </Form>
    </Container>
  );
};

export default RegisterForm;
