import { useState } from "react";
import { motion } from "framer-motion";
import { Activity, RefreshCw, AlertCircle, Database } from "lucide-react";
import GridBackground from "@/components/GridBackground";
import CVETable from "@/components/CVETable";
import LoadingSpinner from "@/components/LoadingSpinner";
import { Button } from "@/components/ui/button";
import { fetchLatestCVEs, CVEItem } from "@/services/api";
import { useToast } from "@/hooks/use-toast";
import RiskBadge from "@/components/RiskBadge";

const RealTimeCVE = () => {
  const [cves, setCves] = useState<CVEItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasFetched, setHasFetched] = useState(false);
  const { toast } = useToast();

  const handleFetch = async () => {
    setLoading(true);
    setError(null);

    try {
      const data = await fetchLatestCVEs();
      setCves(data);
      setHasFetched(true);
      
      const highRiskCount = data.filter((cve) => cve.risk === "HIGH").length;
      const anomalousCount = data.filter((cve) => cve.anomalous).length;
      
      toast({
        title: "CVEs Fetched Successfully",
        description: `Retrieved ${data.length} CVEs (${highRiskCount} high-risk, ${anomalousCount} anomalous)`,
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Failed to fetch CVEs";
      setError(errorMessage);
      toast({
        title: "Fetch Failed",
        description: "Could not connect to the backend. Please ensure the server is running.",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const stats = {
    total: cves.length,
    high: cves.filter((cve) => cve.risk === "HIGH").length,
    medium: cves.filter((cve) => cve.risk === "MEDIUM").length,
    low: cves.filter((cve) => cve.risk === "LOW").length,
    anomalous: cves.filter((cve) => cve.anomalous).length,
  };

  return (
    <div className="relative min-h-screen">
      <GridBackground />
      
      <div className="relative pt-24 pb-20 px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
          >
            <div className="flex items-center gap-4">
              <div className="flex h-14 w-14 items-center justify-center rounded-xl bg-primary/10">
                <Activity className="h-7 w-7 text-primary" />
              </div>
              <div>
                <h1 className="text-3xl font-bold text-foreground">Real-Time CVE Analysis</h1>
                <p className="text-muted-foreground">
                  Monitor and analyze the latest CVEs from NVD
                </p>
              </div>
            </div>
            
            <Button
              onClick={handleFetch}
              disabled={loading}
              className="cyber-glow"
            >
              {loading ? (
                <>
                  <LoadingSpinner size="sm" className="mr-2" />
                  Fetching...
                </>
              ) : (
                <>
                  <RefreshCw className="mr-2 h-4 w-4" />
                  Fetch Latest CVEs
                </>
              )}
            </Button>
          </motion.div>

          {/* Stats Cards */}
          {hasFetched && cves.length > 0 && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-5"
            >
              <div className="rounded-xl border border-border bg-card p-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Total CVEs</span>
                  <Database className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="mt-2 text-2xl font-bold text-foreground">{stats.total}</div>
              </div>
              
              <div className="rounded-xl border border-border bg-card p-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">High Risk</span>
                  <RiskBadge risk="HIGH" size="sm" />
                </div>
                <div className="mt-2 text-2xl font-bold text-destructive">{stats.high}</div>
              </div>
              
              <div className="rounded-xl border border-border bg-card p-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Medium Risk</span>
                  <RiskBadge risk="MEDIUM" size="sm" />
                </div>
                <div className="mt-2 text-2xl font-bold text-warning">{stats.medium}</div>
              </div>
              
              <div className="rounded-xl border border-border bg-card p-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Low Risk</span>
                  <RiskBadge risk="LOW" size="sm" />
                </div>
                <div className="mt-2 text-2xl font-bold text-success">{stats.low}</div>
              </div>
              
              <div className="rounded-xl border border-border bg-card p-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Anomalous</span>
                  <AlertCircle className="h-4 w-4 text-warning" />
                </div>
                <div className="mt-2 text-2xl font-bold text-warning">{stats.anomalous}</div>
              </div>
            </motion.div>
          )}

          {/* Error State */}
          {error && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="mb-8 rounded-xl border border-destructive/30 bg-destructive/10 p-6"
            >
              <div className="flex items-center gap-3">
                <AlertCircle className="h-5 w-5 text-destructive" />
                <div>
                  <h3 className="font-semibold text-destructive">Connection Error</h3>
                  <p className="text-sm text-destructive/80">
                    Could not connect to the backend server at {import.meta.env.VITE_BACKEND_URL || "http://localhost:8000"}. 
                    Please ensure the server is running.
                  </p>
                </div>
              </div>
            </motion.div>
          )}

          {/* Empty State */}
          {!hasFetched && !loading && !error && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="rounded-xl border border-dashed border-border bg-card/50 p-12 text-center"
            >
              <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-muted">
                <Activity className="h-8 w-8 text-muted-foreground" />
              </div>
              <h3 className="mb-2 text-lg font-semibold text-foreground">No CVEs Loaded</h3>
              <p className="mb-6 text-muted-foreground">
                Click the button above to fetch the latest CVEs from the National Vulnerability Database
              </p>
              <Button onClick={handleFetch} disabled={loading}>
                <RefreshCw className="mr-2 h-4 w-4" />
                Fetch Latest CVEs
              </Button>
            </motion.div>
          )}

          {/* Loading State */}
          {loading && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex flex-col items-center justify-center py-20"
            >
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-muted-foreground">Fetching CVEs from NVD...</p>
            </motion.div>
          )}

          {/* CVE Table */}
          {!loading && cves.length > 0 && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              <CVETable cves={cves} />
            </motion.div>
          )}

          {/* No Results State */}
          {hasFetched && !loading && cves.length === 0 && !error && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="rounded-xl border border-border bg-card p-12 text-center"
            >
              <Database className="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
              <h3 className="mb-2 text-lg font-semibold text-foreground">No CVEs Found</h3>
              <p className="text-muted-foreground">
                No CVEs were returned from the server. Try again later.
              </p>
            </motion.div>
          )}
        </div>
      </div>
    </div>
  );
};

export default RealTimeCVE;
