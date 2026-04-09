import { useState } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../auth.jsx";

export function LoginPage() {
  const { isAuthenticated, signIn, signUp } = useAuth();
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (mode === "register") {
        await signUp(form);
      } else {
        await signIn({ email: form.email, password: form.password });
      }
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-shell">
      <section className="auth-panel">
        <p className="eyebrow">Production-Ready MVP</p>
        <h1>Secure access for every scan session</h1>
        <p className="hero-copy">Create an account to persist scan history, download reports, and keep results separated by user context.</p>
      </section>

      <section className="panel auth-form-panel">
        <div className="auth-tabs">
          <button type="button" className={mode === "login" ? "tab-active" : ""} onClick={() => setMode("login")}>Login</button>
          <button type="button" className={mode === "register" ? "tab-active" : ""} onClick={() => setMode("register")}>Register</button>
        </div>

        <form onSubmit={handleSubmit}>
          {mode === "register" ? (
            <label>
              Name
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
          <button type="submit" disabled={busy}>{busy ? "Submitting..." : mode === "login" ? "Login" : "Create Account"}</button>
        </form>
        {error ? <p className="error-text">{error}</p> : null}
      </section>
    </div>
  );
}
