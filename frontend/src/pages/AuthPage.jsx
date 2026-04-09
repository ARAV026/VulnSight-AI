import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { loginUser, registerUser } from "../api";
import { useAuth } from "../auth";

export default function AuthPage({ mode }) {
  const isRegister = mode === "register";
  const navigate = useNavigate();
  const { login } = useAuth();
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const response = isRegister ? await registerUser(form) : await loginUser(form);
      login(response.access_token, response.user);
      navigate("/dashboard");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-shell">
      <section className="panel auth-panel">
        <p className="eyebrow">{isRegister ? "Create Operator Account" : "Authenticate"}</p>
        <h2>{isRegister ? "Register for VulnSight AI" : "Sign in to VulnSight AI"}</h2>
        <form onSubmit={handleSubmit}>
          {isRegister ? (
            <label>
              Full Name
              <input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} required />
            </label>
          ) : null}
          <label>
            Email
            <input type="email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} required />
          </label>
          <label>
            Password
            <input type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} required />
          </label>
          <button type="submit" disabled={loading}>{loading ? "Processing..." : isRegister ? "Create Account" : "Login"}</button>
        </form>
        {error ? <p className="error-text">{error}</p> : null}
        <p className="auth-switch">
          {isRegister ? "Already have an account?" : "Need an account?"}{" "}
          <Link to={isRegister ? "/login" : "/register"}>{isRegister ? "Login" : "Register"}</Link>
        </p>
      </section>
    </div>
  );
}
