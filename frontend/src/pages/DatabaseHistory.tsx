import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Database, Download, FileText, FileSpreadsheet, Activity } from "lucide-react";
import GridBackground from "@/components/GridBackground";
import LoadingSpinner from "@/components/LoadingSpinner";
import { Button } from "@/components/ui/button";
import { getHistory, getExportUrl, HistoryResponse } from "@/services/api";
import RiskBadge from "@/components/RiskBadge";

const DatabaseHistory = () => {
  const [data, setData] = useState<HistoryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const history = await getHistory(50);
        setData(history);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load history");
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const handleExport = (type: "csv" | "pdf") => {
    window.open(getExportUrl(type), "_blank");
  };

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
            className="mb-8 flex flex-col md:flex-row md:items-end justify-between gap-4"
          >
            <div>
              <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-xl bg-primary/10">
                <Database className="h-7 w-7 text-primary" />
              </div>
              <h1 className="text-3xl font-bold text-foreground">Prediction History</h1>
              <p className="mt-2 text-muted-foreground">
                View past vulnerability predictions and export professional reports
              </p>
            </div>
            <div className="flex gap-3">
              <Button onClick={() => handleExport("csv")} variant="outline" className="gap-2">
                <FileSpreadsheet className="h-4 w-4" /> CSV
              </Button>
              <Button onClick={() => handleExport("pdf")} className="gap-2 cyber-glow">
                <Download className="h-4 w-4" /> Export PDF
              </Button>
            </div>
          </motion.div>

          {loading ? (
            <div className="flex justify-center py-20">
              <LoadingSpinner size="lg" />
            </div>
          ) : error ? (
            <div className="rounded-xl border border-destructive bg-destructive/10 p-6 text-center text-destructive">
              {error}
            </div>
          ) : !data || data.records.length === 0 ? (
            <div className="rounded-xl border border-border bg-card p-12 text-center text-muted-foreground">
              <Database className="mx-auto h-12 w-12 opacity-20 mb-4" />
              <p>No prediction history found.</p>
              <p className="text-sm">Run some predictions to see them here.</p>
            </div>
          ) : (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="space-y-6"
            >
              {/* Stats Row */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="rounded-xl border border-border bg-card p-4">
                  <p className="text-sm font-medium text-muted-foreground mb-1">Total Records</p>
                  <p className="text-2xl font-bold">{data.stats.total_predictions}</p>
                </div>
                <div className="rounded-xl border border-border bg-card p-4 risk-glow-high">
                  <p className="text-sm font-medium text-muted-foreground mb-1">High Risk</p>
                  <p className="text-2xl font-bold text-destructive">{data.stats.risk_distribution.HIGH}</p>
                </div>
                <div className="rounded-xl border border-border bg-card p-4 risk-glow-medium">
                  <p className="text-sm font-medium text-muted-foreground mb-1">Medium Risk</p>
                  <p className="text-2xl font-bold text-warning">{data.stats.risk_distribution.MEDIUM}</p>
                </div>
                <div className="rounded-xl border border-border bg-card p-4 risk-glow-low">
                  <p className="text-sm font-medium text-muted-foreground mb-1">Low Risk</p>
                  <p className="text-2xl font-bold text-success">{data.stats.risk_distribution.LOW}</p>
                </div>
              </div>

              {/* Table */}
              <div className="rounded-xl border border-border bg-card overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm text-left text-muted-foreground">
                    <thead className="text-xs text-foreground uppercase bg-muted/50 border-b border-border">
                      <tr>
                        <th className="px-6 py-4 font-semibold">Date</th>
                        <th className="px-6 py-4 font-semibold">Risk Level</th>
                        <th className="px-6 py-4 font-semibold">CVSS</th>
                        <th className="px-6 py-4 font-semibold">Description</th>
                        <th className="px-6 py-4 font-semibold">Source</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {data.records.map((record) => (
                        <tr key={record.id} className="hover:bg-muted/30 transition-colors">
                          <td className="px-6 py-4 whitespace-nowrap font-mono text-xs">
                            {new Date(record.created_at).toLocaleString()}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <RiskBadge risk={record.risk} size="sm" />
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            {record.cvss_predicted ? (
                              <div className="flex items-center gap-1.5 font-medium">
                                <Activity className="h-3.5 w-3.5" />
                                {record.cvss_predicted.toFixed(1)}
                              </div>
                            ) : (
                              <span className="text-muted-foreground/50">-</span>
                            )}
                          </td>
                          <td className="px-6 py-4">
                            <p className="line-clamp-2 max-w-md text-xs">{record.description}</p>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap capitalize text-xs">
                            {record.source.replace('_', ' ')}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </motion.div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DatabaseHistory;
