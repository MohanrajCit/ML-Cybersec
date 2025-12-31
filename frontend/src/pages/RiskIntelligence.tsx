import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { 
  Shield, 
  AlertTriangle, 
  Activity, 
  TrendingUp, 
  Info,
  RefreshCw
} from "lucide-react";
import GridBackground from "@/components/GridBackground";
import LoadingSpinner from "@/components/LoadingSpinner";
import { Button } from "@/components/ui/button";
import { fetchLatestCVEs, CVEItem } from "@/services/api";
import { useToast } from "@/hooks/use-toast";

interface MetricCardProps {
  label: string;
  value: number;
  icon: React.ReactNode;
  variant?: "default" | "high" | "medium" | "low";
}

const MetricCard = ({ label, value, icon, variant = "default" }: MetricCardProps) => {
  const variantClasses = {
    default: "border-border",
    high: "border-destructive/30 bg-destructive/5",
    medium: "border-warning/30 bg-warning/5",
    low: "border-success/30 bg-success/5",
  };

  const valueClasses = {
    default: "text-foreground",
    high: "text-destructive",
    medium: "text-warning",
    low: "text-success",
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={`rounded-xl border bg-card p-6 ${variantClasses[variant]}`}
    >
      <div className="flex items-center justify-between">
        <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-secondary">
          {icon}
        </div>
      </div>
      <div className="mt-4">
        <p className={`text-4xl font-bold ${valueClasses[variant]}`}>{value}</p>
        <p className="mt-1 text-sm text-muted-foreground">{label}</p>
      </div>
    </motion.div>
  );
};

const RiskIntelligence = () => {
  const [cves, setCves] = useState<CVEItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchLatestCVEs();
      setCves(data);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Failed to fetch CVE data";
      setError(errorMessage);
      toast({
        title: "Data Fetch Failed",
        description: "Could not connect to the prediction service.",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Compute metrics
  const totalCVEs = cves.length;
  const highRiskCount = cves.filter((c) => c.risk === "HIGH").length;
  const mediumRiskCount = cves.filter((c) => c.risk === "MEDIUM").length;
  const lowRiskCount = cves.filter((c) => c.risk === "LOW").length;
  const anomalousCount = cves.filter((c) => c.anomalous).length;
  const anomalousPercentage = totalCVEs > 0 ? Math.round((anomalousCount / totalCVEs) * 100) : 0;

  // Generate insights
  const insights: { icon: string; text: string; type: "warning" | "alert" | "info" }[] = [];
  
  if (highRiskCount > 0) {
    insights.push({
      icon: "⚠️",
      text: `${highRiskCount} high-risk ${highRiskCount === 1 ? "vulnerability" : "vulnerabilities"} detected that may require immediate attention.`,
      type: "warning",
    });
  }
  
  if (anomalousCount > 0) {
    insights.push({
      icon: "🚨",
      text: `${anomalousCount} anomalous ${anomalousCount === 1 ? "CVE" : "CVEs"} identified in recent disclosures.`,
      type: "alert",
    });
  }
  
  if (highRiskCount === 0 && anomalousCount === 0 && totalCVEs > 0) {
    insights.push({
      icon: "✅",
      text: "No critical risks or anomalies detected in the current dataset.",
      type: "info",
    });
  }

  if (totalCVEs > 0 && mediumRiskCount > highRiskCount) {
    insights.push({
      icon: "📊",
      text: `${mediumRiskCount} medium-risk vulnerabilities should be reviewed for potential escalation.`,
      type: "info",
    });
  }

  return (
    <div className="relative min-h-screen">
      <GridBackground />
      
      <div className="relative pt-24 pb-20 px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-6xl">
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
          >
            <div>
              <div className="mb-2 flex items-center gap-3">
                <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10">
                  <Activity className="h-6 w-6 text-primary" />
                </div>
                <h1 className="text-3xl font-bold text-foreground">Risk Intelligence</h1>
              </div>
              <p className="text-muted-foreground">
                SOC-style security insights from ML-based CVE risk predictions
              </p>
            </div>
            <Button onClick={fetchData} disabled={loading} variant="outline">
              <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
              Refresh Data
            </Button>
          </motion.div>

          {loading ? (
            <div className="flex h-64 items-center justify-center">
              <LoadingSpinner size="lg" />
            </div>
          ) : error ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="rounded-xl border border-destructive/30 bg-destructive/10 p-6 text-center"
            >
              <AlertTriangle className="mx-auto h-10 w-10 text-destructive" />
              <p className="mt-3 text-destructive">{error}</p>
              <Button onClick={fetchData} className="mt-4">
                Retry
              </Button>
            </motion.div>
          ) : (
            <>
              {/* Summary Metric Cards */}
              <section className="mb-10">
                <h2 className="mb-4 text-lg font-semibold text-foreground">Risk Summary</h2>
                <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                  <MetricCard
                    label="Total CVEs Analyzed"
                    value={totalCVEs}
                    icon={<Shield className="h-6 w-6 text-primary" />}
                  />
                  <MetricCard
                    label="HIGH Risk CVEs"
                    value={highRiskCount}
                    icon={<AlertTriangle className="h-6 w-6 text-destructive" />}
                    variant="high"
                  />
                  <MetricCard
                    label="MEDIUM Risk CVEs"
                    value={mediumRiskCount}
                    icon={<TrendingUp className="h-6 w-6 text-warning" />}
                    variant="medium"
                  />
                  <MetricCard
                    label="LOW Risk CVEs"
                    value={lowRiskCount}
                    icon={<Shield className="h-6 w-6 text-success" />}
                    variant="low"
                  />
                </div>
              </section>

              {/* Anomaly Overview Section */}
              <motion.section
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
                className="mb-10 rounded-xl border border-border bg-card p-6"
              >
                <h2 className="mb-4 text-lg font-semibold text-foreground">Anomaly Overview</h2>
                <div className="flex flex-col gap-6 md:flex-row md:items-center">
                  <div className="flex-1">
                    <div className="mb-2 flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Anomalous vs Normal</span>
                      <span className="font-medium text-foreground">
                        {anomalousCount} of {totalCVEs} ({anomalousPercentage}%)
                      </span>
                    </div>
                    <div className="h-3 overflow-hidden rounded-full bg-secondary">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${anomalousPercentage}%` }}
                        transition={{ duration: 0.8, delay: 0.2 }}
                        className="h-full bg-warning"
                      />
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-sm">
                    <div className="flex items-center gap-2">
                      <div className="h-3 w-3 rounded-full bg-warning" />
                      <span className="text-muted-foreground">Anomalous</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="h-3 w-3 rounded-full bg-secondary" />
                      <span className="text-muted-foreground">Normal</span>
                    </div>
                  </div>
                </div>
                <p className="mt-4 text-sm text-muted-foreground">
                  Anomalous vulnerabilities may indicate unusual patterns or potential zero-day risks.
                </p>
              </motion.section>

              {/* Risk Posture Insights */}
              {insights.length > 0 && (
                <motion.section
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 }}
                  className="mb-10"
                >
                  <h2 className="mb-4 text-lg font-semibold text-foreground">Risk Posture Insights</h2>
                  <div className="space-y-3">
                    {insights.map((insight, index) => (
                      <motion.div
                        key={index}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: 0.3 + index * 0.1 }}
                        className={`flex items-start gap-3 rounded-lg border p-4 ${
                          insight.type === "warning"
                            ? "border-warning/30 bg-warning/5"
                            : insight.type === "alert"
                            ? "border-destructive/30 bg-destructive/5"
                            : "border-border bg-card"
                        }`}
                      >
                        <span className="text-xl">{insight.icon}</span>
                        <p className="text-sm text-foreground">{insight.text}</p>
                      </motion.div>
                    ))}
                  </div>
                </motion.section>
              )}

              {/* Decision Support Disclaimer */}
              <motion.section
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
                className="rounded-xl border border-primary/20 bg-primary/5 p-5"
              >
                <div className="flex items-start gap-3">
                  <Info className="mt-0.5 h-5 w-5 flex-shrink-0 text-primary" />
                  <div>
                    <h3 className="text-sm font-medium text-foreground">Decision Support Disclaimer</h3>
                    <p className="mt-1 text-sm text-muted-foreground">
                      This system provides early-stage ML-based risk estimation to support security decision-making.
                      It does not replace CVSS scoring or expert analysis.
                    </p>
                  </div>
                </div>
              </motion.section>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default RiskIntelligence;
