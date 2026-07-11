import { motion } from "framer-motion";
import { ExplainResponse } from "@/services/api";
import { Brain, FileCode, CheckCircle2, AlertTriangle, Key } from "lucide-react";

interface ExplainabilityPanelProps {
  explanation: ExplainResponse;
}

const ExplainabilityPanel = ({ explanation }: ExplainabilityPanelProps) => {
  return (
    <div className="mt-4 rounded-xl border border-border bg-card overflow-hidden">
      <div className="border-b border-border bg-muted/30 px-4 py-3 flex items-center gap-2">
        <Brain className="h-4 w-4 text-primary" />
        <h4 className="font-semibold text-sm">AI Reasoning & Explainability</h4>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4">
        
        {/* Keyword Boosts */}
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
            <AlertTriangle className="h-4 w-4" />
            Detected Threat Patterns
          </div>
          
          {explanation.keyword_matches.length > 0 ? (
            <div className="space-y-2">
              {explanation.keyword_matches.map((kw, i) => (
                <div key={i} className="flex justify-between items-center rounded bg-destructive/10 px-3 py-2 text-sm border border-destructive/20">
                  <span className="font-mono text-destructive font-medium">{kw.keyword}</span>
                  <span className="text-xs font-bold text-destructive">{kw.boost} boost</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded bg-muted/30 px-3 py-2 text-sm text-muted-foreground flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4" />
              No critical manual heuristics triggered
            </div>
          )}

          <div className="pt-2">
             <div className="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-2">
               <Key className="h-4 w-4" />
               Authentication Context
             </div>
             <div className="rounded bg-muted/30 px-3 py-2 text-sm capitalize border border-border">
               {explanation.auth_context.replace('_', ' ')}
             </div>
          </div>
        </div>

        {/* Top Features */}
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
            <FileCode className="h-4 w-4" />
            Top TF-IDF Features
          </div>
          <div className="rounded-lg border border-border bg-background overflow-hidden">
            <table className="w-full text-xs text-left">
              <thead className="bg-muted/50 text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 font-medium">Term</th>
                  <th className="px-3 py-2 font-medium text-right">TF-IDF Weight</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {explanation.top_features.map((feature, i) => (
                  <tr key={i} className="hover:bg-muted/30 transition-colors">
                    <td className="px-3 py-1.5 font-mono text-foreground">{feature.term}</td>
                    <td className="px-3 py-1.5 text-right font-mono text-muted-foreground">
                      {feature.tfidf_weight.toFixed(4)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ExplainabilityPanel;
