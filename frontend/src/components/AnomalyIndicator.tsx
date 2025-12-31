import { AlertTriangle, CheckCircle } from "lucide-react";
import { cn } from "@/lib/utils";

interface AnomalyIndicatorProps {
  anomalous: boolean;
  showLabel?: boolean;
}

const AnomalyIndicator = ({ anomalous, showLabel = true }: AnomalyIndicatorProps) => {
  return (
    <div
      className={cn(
        "inline-flex items-center gap-2 rounded-md px-3 py-1 text-sm font-medium",
        anomalous
          ? "bg-warning/10 text-warning"
          : "bg-success/10 text-success"
      )}
    >
      {anomalous ? (
        <AlertTriangle className="h-4 w-4" />
      ) : (
        <CheckCircle className="h-4 w-4" />
      )}
      {showLabel && (
        <span>{anomalous ? "Anomalous" : "Normal"}</span>
      )}
    </div>
  );
};

export default AnomalyIndicator;
