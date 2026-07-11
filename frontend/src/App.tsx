import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { ThemeProvider } from "@/context/ThemeContext";
import Navbar from "@/components/Navbar";
import Landing from "./pages/Landing";
import ManualAnalysis from "./pages/ManualAnalysis";
import RealTimeCVE from "./pages/RealTimeCVE";
import DatabaseHistory from "./pages/DatabaseHistory";
import RiskIntelligence from "./pages/RiskIntelligence";
import NotFound from "./pages/NotFound";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Compare from "./pages/Compare";
import { AuthProvider } from "./context/AuthContext";
import { WebSocketProvider } from "./context/WebSocketContext";

const queryClient = new QueryClient();

const App = () => (
  <AuthProvider>
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <TooltipProvider>
          <WebSocketProvider>
            <Toaster />
            <Sonner />
            <BrowserRouter>
              <Navbar />
              <Routes>
                <Route path="/" element={<Landing />} />
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="/analyze" element={<ManualAnalysis />} />
                <Route path="/realtime" element={<RealTimeCVE />} />
                <Route path="/history" element={<DatabaseHistory />} />
                <Route path="/compare" element={<Compare />} />
                <Route path="/risk-intelligence" element={<RiskIntelligence />} />
                <Route path="*" element={<NotFound />} />
              </Routes>
            </BrowserRouter>
          </WebSocketProvider>
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  </AuthProvider>
);

export default App;
