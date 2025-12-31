import { cn } from "@/lib/utils";

interface RiskBadgeProps {
  risk: "HIGH" | "MEDIUM" | "LOW";
  size?: "sm" | "md" | "lg";
}

const RiskBadge = ({ risk, size = "md" }: RiskBadgeProps) => {
  const sizeClasses = {
    sm: "px-2 py-0.5 text-xs",
    md: "px-3 py-1 text-sm",
    lg: "px-4 py-1.5 text-base",
  };

  const riskClasses = {
    HIGH: "bg-destructive/15 text-destructive border-destructive/30",
    MEDIUM: "bg-warning/15 text-warning border-warning/30",
    LOW: "bg-success/15 text-success border-success/30",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border font-semibold",
        sizeClasses[size],
        riskClasses[risk]
      )}
    >
      {risk}
    </span>
  );
};

export default RiskBadge;
