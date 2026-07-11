import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { User, Lock, Mail, ArrowRight } from 'lucide-react';
import { registerUser } from '@/services/api';
import { useToast } from '@/hooks/use-toast';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

const Register: React.FC = () => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { toast } = useToast();

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !email || !password) return;
    
    setLoading(true);
    try {
      await registerUser({ username, email, password });
      toast({
        title: "Success",
        description: "Account created successfully. Please sign in.",
        variant: "default",
      });
      navigate('/login');
    } catch (error: any) {
      toast({
        title: "Registration Failed",
        description: error.response?.data?.detail || "Could not create account. Please try again.",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-[80vh]">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md p-8 space-y-8 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl"
      >
        <div className="text-center">
          <h2 className="text-3xl font-bold tracking-tight text-white">Create Account</h2>
          <p className="mt-2 text-sm text-slate-400">Join CyberSpec to track vulnerability predictions</p>
        </div>

        <form onSubmit={handleRegister} className="space-y-6">
          <div className="space-y-4">
            <div className="relative">
              <User className="absolute left-3 top-3 h-5 w-5 text-slate-400" />
              <Input
                type="text"
                placeholder="Username"
                className="pl-10 bg-slate-800 border-slate-700 text-white placeholder:text-slate-500 h-12"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <div className="relative">
              <Mail className="absolute left-3 top-3 h-5 w-5 text-slate-400" />
              <Input
                type="email"
                placeholder="Email Address"
                className="pl-10 bg-slate-800 border-slate-700 text-white placeholder:text-slate-500 h-12"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <div className="relative">
              <Lock className="absolute left-3 top-3 h-5 w-5 text-slate-400" />
              <Input
                type="password"
                placeholder="Password"
                className="pl-10 bg-slate-800 border-slate-700 text-white placeholder:text-slate-500 h-12"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
          </div>

          <Button 
            type="submit" 
            className="w-full h-12 text-md font-semibold bg-emerald-600 hover:bg-emerald-700 text-white flex items-center justify-center gap-2"
            disabled={loading}
          >
            {loading ? "Creating account..." : (
              <>Sign Up <ArrowRight className="w-5 h-5" /></>
            )}
          </Button>
        </form>

        <p className="text-center text-sm text-slate-400">
          Already have an account?{' '}
          <Link to="/login" className="font-semibold text-emerald-500 hover:text-emerald-400">
            Sign in
          </Link>
        </p>
      </motion.div>
    </div>
  );
};

export default Register;
