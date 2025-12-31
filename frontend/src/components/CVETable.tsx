import { CVEItem } from "@/services/api";
import RiskBadge from "./RiskBadge";
import AnomalyIndicator from "./AnomalyIndicator";
import { motion } from "framer-motion";

interface CVETableProps {
  cves: CVEItem[];
}

const CVETable = ({ cves }: CVETableProps) => {
  return (
    <div className="overflow-hidden rounded-xl border border-border">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border bg-muted/50">
              <th className="whitespace-nowrap px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                CVE ID
              </th>
              <th className="whitespace-nowrap px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Risk Level
              </th>
              <th className="whitespace-nowrap px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Confidence
              </th>
              <th className="whitespace-nowrap px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Status
              </th>
              <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Description
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border bg-card">
            {cves.map((cve, index) => (
              <motion.tr
                key={cve.cve_id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3, delay: index * 0.05 }}
                className={`transition-colors hover:bg-muted/30 ${
                  cve.risk === "HIGH" ? "border-l-2 border-l-destructive" : ""
                }`}
              >
                <td className="whitespace-nowrap px-6 py-4">
                  <span className="font-mono text-sm font-medium text-foreground">
                    {cve.cve_id}
                  </span>
                </td>
                <td className="whitespace-nowrap px-6 py-4">
                  <RiskBadge risk={cve.risk} size="sm" />
                </td>
                <td className="whitespace-nowrap px-6 py-4">
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 w-16 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full bg-primary"
                        style={{ width: `${Math.round(cve.confidence * 100)}%` }}
                      />
                    </div>
                    <span className="font-mono text-xs text-muted-foreground">
                      {Math.round(cve.confidence * 100)}%
                    </span>
                  </div>
                </td>
                <td className="whitespace-nowrap px-6 py-4">
                  <AnomalyIndicator anomalous={cve.anomalous} showLabel={false} />
                </td>
                <td className="max-w-md px-6 py-4">
                  <p className="line-clamp-2 text-sm text-muted-foreground">
                    {cve.description}
                  </p>
                </td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default CVETable;
