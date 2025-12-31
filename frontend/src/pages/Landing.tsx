import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, Search, Activity, AlertTriangle, ArrowRight, Zap, Radar } from "lucide-react";
import FeatureCard from "@/components/FeatureCard";
import GridBackground from "@/components/GridBackground";
import { Button } from "@/components/ui/button";

const Landing = () => {
  const features = [
    {
      icon: Search,
      title: "Manual CVE Analysis",
      description: "Enter any vulnerability description for instant ML-based risk classification and threat assessment.",
    },
    {
      icon: Activity,
      title: "Real-Time NVD Monitoring",
      description: "Track and analyze the latest CVEs from the National Vulnerability Database as they're disclosed.",
    },
    {
      icon: Zap,
      title: "ML-Based Risk Prediction",
      description: "Advanced machine learning models classify vulnerabilities into HIGH, MEDIUM, or LOW risk levels.",
    },
    {
      icon: AlertTriangle,
      title: "Anomaly Detection",
      description: "Identify unusual vulnerabilities that deviate from typical patterns for prioritized investigation.",
    },
  ];

  return (
    <div className="relative min-h-screen overflow-hidden">
      <GridBackground />
      
      {/* Hero Section */}
      <section className="relative pt-32 pb-20 px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="text-center">
            {/* Badge */}
            <motion.div
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              className="mb-6 inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/5 px-4 py-1.5 text-sm font-medium text-primary"
            >
              <Radar className="h-4 w-4" />
              ML-Powered Security Intelligence
            </motion.div>

            {/* Main Title */}
            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="text-4xl font-bold tracking-tight text-foreground sm:text-5xl lg:text-6xl"
            >
              <span className="block">CVE Risk</span>
              <span className="block bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
                Prediction System
              </span>
            </motion.h1>

            {/* Tagline */}
            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="mx-auto mt-6 max-w-2xl text-lg text-muted-foreground sm:text-xl"
            >
              Early Risk Estimation for Software Vulnerabilities using Machine Learning
            </motion.p>

            {/* CTA Buttons */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
              className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row"
            >
              <Button asChild size="lg" className="group min-w-[180px] cyber-glow">
                <Link to="/analyze">
                  Analyze Manually
                  <ArrowRight className="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1" />
                </Link>
              </Button>
              <Button asChild variant="outline" size="lg" className="min-w-[180px]">
                <Link to="/realtime">
                  <Activity className="mr-2 h-4 w-4" />
                  View Real-Time CVEs
                </Link>
              </Button>
            </motion.div>
          </div>

          {/* Stats */}
          <motion.div
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.5 }}
            className="mx-auto mt-20 grid max-w-3xl grid-cols-3 gap-8"
          >
            {[
              { value: "3", label: "Risk Levels" },
              { value: "ML", label: "Powered Analysis" },
              { value: "24/7", label: "Real-Time Monitoring" },
            ].map((stat, index) => (
              <div key={index} className="text-center">
                <div className="text-3xl font-bold text-primary sm:text-4xl">{stat.value}</div>
                <div className="mt-1 text-sm text-muted-foreground">{stat.label}</div>
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Features Section */}
      <section className="relative py-20 px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="mb-12 text-center">
            <h2 className="text-3xl font-bold text-foreground">Core Capabilities</h2>
            <p className="mt-3 text-muted-foreground">
              Comprehensive vulnerability analysis powered by machine learning
            </p>
          </div>

          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {features.map((feature, index) => (
              <FeatureCard
                key={index}
                icon={feature.icon}
                title={feature.title}
                description={feature.description}
                delay={0.1 * index}
              />
            ))}
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section className="relative py-20 px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="mb-12 text-center">
            <h2 className="text-3xl font-bold text-foreground">How It Works</h2>
            <p className="mt-3 text-muted-foreground">
              Three simple steps to security insights
            </p>
          </div>

          <div className="mx-auto max-w-4xl">
            <div className="grid gap-8 md:grid-cols-3">
              {[
                {
                  step: "01",
                  title: "Input Vulnerability",
                  description: "Enter a CVE description or fetch live data from NVD",
                },
                {
                  step: "02",
                  title: "ML Analysis",
                  description: "Our models classify risk level and detect anomalies",
                },
                {
                  step: "03",
                  title: "Get Results",
                  description: "Receive actionable risk assessment with confidence scores",
                },
              ].map((item, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5, delay: 0.2 + index * 0.1 }}
                  className="relative text-center"
                >
                  <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-xl bg-primary/10 font-mono text-xl font-bold text-primary">
                    {item.step}
                  </div>
                  <h3 className="mb-2 text-lg font-semibold text-foreground">{item.title}</h3>
                  <p className="text-sm text-muted-foreground">{item.description}</p>
                  
                  {index < 2 && (
                    <div className="absolute right-0 top-6 hidden -translate-y-1/2 translate-x-1/2 md:block">
                      <ArrowRight className="h-5 w-5 text-muted-foreground/30" />
                    </div>
                  )}
                </motion.div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border py-8 px-4">
        <div className="mx-auto max-w-7xl text-center">
          <div className="flex items-center justify-center gap-2 text-muted-foreground">
            <Shield className="h-5 w-5 text-primary" />
            <span className="text-sm">CVE Risk Prediction System</span>
          </div>
          <p className="mt-2 text-xs text-muted-foreground/60">
            ML-Powered Vulnerability Analysis for Security Teams
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
