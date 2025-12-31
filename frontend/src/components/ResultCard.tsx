import { motion } from "framer-motion";
import { PredictResponse } from "@/services/api";
import RiskBadge from "./RiskBadge";
import ConfidenceBar from "./ConfidenceBar";
import AnomalyIndicator from "./AnomalyIndicator";
import { Info } from "lucide-react";

interface ResultCardProps {
  result: PredictResponse;
}

const ResultCard = ({ result }: ResultCardProps) => {
  const glowClass = {
    HIGH: "risk-glow-high",
    MEDIUM: "risk-glow-medium",
    LOW: "risk-glow-low",
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.4 }}
      className={`rounded-xl border border-border bg-card p-6 ${glowClass[result.risk]}`}
    >
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h3 className="mb-1 text-sm font-medium text-muted-foreground">Risk Assessment</h3>
          <RiskBadge risk={result.risk} size="lg" />
        </div>
        <AnomalyIndicator anomalous={result.anomalous} />
      </div>

      <div className="mb-6">
        <ConfidenceBar value={result.confidence} />
      </div>

      <div className="rounded-lg bg-muted/50 p-4">
        <div className="flex items-start gap-3">
          <Info className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
          <div>
            <p className="text-sm leading-relaxed text-muted-foreground">
              This description was classified based on learned CVE patterns. 
              {result.anomalous && (
                <span className="ml-1 text-warning">
                  This vulnerability exhibits unusual characteristics that deviate from typical patterns.
                </span>
              )}
            </p>
            <p className="mt-2 font-mono text-xs text-muted-foreground">
              Anomaly Score: {result.anomaly_score.toFixed(4)}
            </p>
          </div>
        </div>
      </div>
    </motion.div>
  );
};

export default ResultCard;
