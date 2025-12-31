import { motion } from "framer-motion";

interface ConfidenceBarProps {
  value: number;
  label?: string;
}

const ConfidenceBar = ({ value, label = "Confidence" }: ConfidenceBarProps) => {
  const percentage = Math.round(value * 100);
  
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-sm">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-mono font-semibold text-foreground">{percentage}%</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-muted">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${percentage}%` }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className="h-full rounded-full bg-primary"
        />
      </div>
    </div>
  );
};

export default ConfidenceBar;
