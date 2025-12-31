import { useState } from "react";
import { motion } from "framer-motion";
import { Search, FileText, AlertCircle } from "lucide-react";
import GridBackground from "@/components/GridBackground";
import ResultCard from "@/components/ResultCard";
import LoadingSpinner from "@/components/LoadingSpinner";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { predictRisk, PredictResponse } from "@/services/api";
import { useToast } from "@/hooks/use-toast";

const ManualAnalysis = () => {
  const [description, setDescription] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PredictResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  const handleAnalyze = async () => {
    if (!description.trim()) {
      setError("Please enter a vulnerability description");
      toast({
        title: "Validation Error",
        description: "Please enter a vulnerability description to analyze",
        variant: "destructive",
      });
      return;
    }

    setError(null);
    setLoading(true);
    setResult(null);

    try {
      const response = await predictRisk({ description: description.trim() });
      setResult(response);
      toast({
        title: "Analysis Complete",
        description: `Risk Level: ${response.risk} (${Math.round(response.confidence * 100)}% confidence)`,
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Failed to analyze vulnerability";
      setError(errorMessage);
      toast({
        title: "Analysis Failed",
        description: "Could not connect to the prediction service. Please ensure the backend is running.",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setDescription("");
    setResult(null);
    setError(null);
  };

  return (
    <div className="relative min-h-screen">
      <GridBackground />
      
      <div className="relative pt-24 pb-20 px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-3xl">
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="mb-8 text-center"
          >
            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-xl bg-primary/10">
              <FileText className="h-7 w-7 text-primary" />
            </div>
            <h1 className="text-3xl font-bold text-foreground">Manual Vulnerability Analysis</h1>
            <p className="mt-2 text-muted-foreground">
              Enter a CVE description to get ML-based risk prediction and anomaly detection
            </p>
          </motion.div>

          {/* Input Section */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="rounded-xl border border-border bg-card p-6"
          >
            <label htmlFor="description" className="mb-2 block text-sm font-medium text-foreground">
              Vulnerability Description
            </label>
            <Textarea
              id="description"
              value={description}
              onChange={(e) => {
                setDescription(e.target.value);
                if (error) setError(null);
              }}
              placeholder="Enter the CVE or vulnerability description here...

Example: A buffer overflow vulnerability in the HTTP parser of Application X allows remote attackers to execute arbitrary code via a crafted request..."
              className={`min-h-[180px] resize-none font-mono text-sm ${
                error ? "border-destructive focus-visible:ring-destructive" : ""
              }`}
            />
            
            {error && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className="mt-2 flex items-center gap-2 text-sm text-destructive"
              >
                <AlertCircle className="h-4 w-4" />
                {error}
              </motion.div>
            )}

            <div className="mt-4 flex flex-col gap-3 sm:flex-row">
              <Button
                onClick={handleAnalyze}
                disabled={loading}
                className="flex-1 cyber-glow"
              >
                {loading ? (
                  <>
                    <LoadingSpinner size="sm" className="mr-2" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Search className="mr-2 h-4 w-4" />
                    Analyze Vulnerability
                  </>
                )}
              </Button>
              <Button
                variant="outline"
                onClick={handleClear}
                disabled={loading}
              >
                Clear
              </Button>
            </div>
          </motion.div>

          {/* Result Section */}
          {result && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              className="mt-8"
            >
              <h2 className="mb-4 text-lg font-semibold text-foreground">Analysis Results</h2>
              <ResultCard result={result} />
            </motion.div>
          )}

        </div>
      </div>
    </div>
  );
};

export default ManualAnalysis;
