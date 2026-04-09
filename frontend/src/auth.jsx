import { createContext, useContext, useEffect, useState } from "react";
import { getCurrentUser, login, register } from "./api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [bootstrapped, setBootstrapped] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("vulnsight_token");
    if (!token) {
      setBootstrapped(true);
      return;
    }

    getCurrentUser()
      .then(setUser)
      .catch(() => {
        localStorage.removeItem("vulnsight_token");
        setUser(null);
      })
      .finally(() => setBootstrapped(true));
  }, []);

  async function signIn(payload) {
    const response = await login(payload);
    localStorage.setItem("vulnsight_token", response.access_token);
    setUser(response.user);
    return response;
  }

  async function signUp(payload) {
    const response = await register(payload);
    localStorage.setItem("vulnsight_token", response.access_token);
    setUser(response.user);
    return response;
  }

  function signOut() {
    localStorage.removeItem("vulnsight_token");
    setUser(null);
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        bootstrapped,
        isAuthenticated: Boolean(user),
        signIn,
        signUp,
        signOut
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
