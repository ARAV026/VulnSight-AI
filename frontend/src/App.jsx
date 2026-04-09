import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth.jsx";
import { AppLayout } from "./components/AppLayout.jsx";
import { HomePage } from "./pages/HomePage.jsx";
import { HistoryPage } from "./pages/HistoryPage.jsx";
import { LoginPage } from "./pages/LoginPage.jsx";
import { ReportsPage } from "./pages/ReportsPage.jsx";
import { ScanPage } from "./pages/ScanPage.jsx";

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<ProtectedLayout />}>
          <Route path="/" element={<HomePage />} />
          <Route path="/scan" element={<ScanPage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/reports" element={<ReportsPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}

function ProtectedLayout() {
  const { isAuthenticated, bootstrapped } = useAuth();

  if (!bootstrapped) {
    return <div className="boot-screen">Loading VulnSight AI...</div>;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <AppLayout />;
}
