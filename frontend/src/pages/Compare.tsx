import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, GitCompare, Search, X } from 'lucide-react';
import { getHistory, HistoryRecord } from '@/services/api';
import GridBackground from '@/components/GridBackground';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

const Compare: React.FC = () => {
  const [records, setRecords] = useState<HistoryRecord[]>([]);
  const [selectedRecords, setSelectedRecords] = useState<HistoryRecord[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchRecords = async () => {
      try {
        const data = await getHistory(100);
        setRecords(data.records);
      } catch (error) {
        console.error("Failed to load history", error);
      } finally {
        setLoading(false);
      }
    };
    fetchRecords();
  }, []);

  const filteredRecords = records.filter(r => 
    r.description.toLowerCase().includes(searchTerm.toLowerCase()) || 
    (r.cve_id && r.cve_id.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const toggleRecord = (record: HistoryRecord) => {
    if (selectedRecords.find(r => r.id === record.id)) {
      setSelectedRecords(selectedRecords.filter(r => r.id !== record.id));
    } else {
      if (selectedRecords.length < 3) {
        setSelectedRecords([...selectedRecords, record]);
      }
    }
  };

  return (
    <div className="relative min-h-screen pb-20 pt-24">
      <GridBackground />
      
      <div className="relative z-10 mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <div className="flex items-center gap-3 mb-2">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-500/20 text-blue-500">
              <GitCompare className="h-5 w-5" />
            </div>
            <h1 className="text-3xl font-bold tracking-tight text-white">Compare Vulnerabilities</h1>
          </div>
          <p className="text-slate-400">Select up to 3 CVEs to compare their risks, CVSS scores, and anomaly data side-by-side.</p>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          
          {/* Left Column: Search & Selection List */}
          <div className="lg:col-span-1 space-y-4 border-r border-slate-800 pr-4">
            <div className="relative">
              <Search className="absolute left-3 top-3 h-4 w-4 text-slate-500" />
              <Input
                type="text"
                placeholder="Search historical CVEs..."
                className="pl-9 bg-slate-900 border-slate-800"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
            
            <div className="h-[600px] overflow-y-auto space-y-2 pr-2 custom-scrollbar">
              {loading ? (
                <div className="text-slate-500 text-sm">Loading history...</div>
              ) : filteredRecords.map(record => {
                const isSelected = selectedRecords.some(r => r.id === record.id);
                return (
                  <div 
                    key={record.id}
                    onClick={() => toggleRecord(record)}
                    className={`p-3 rounded-lg border cursor-pointer transition-all ${
                      isSelected 
                        ? 'bg-blue-900/30 border-blue-500/50' 
                        : 'bg-slate-900/50 border-slate-800 hover:border-slate-700 hover:bg-slate-800/50'
                    }`}
                  >
                    <div className="flex justify-between items-start mb-1">
                      <span className="font-mono text-xs text-slate-300 font-semibold">{record.cve_id || `ID: ${record.id}`}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                        record.risk === 'HIGH' ? 'bg-red-500/20 text-red-400' :
                        record.risk === 'MEDIUM' ? 'bg-orange-500/20 text-orange-400' :
                        'bg-emerald-500/20 text-emerald-400'
                      }`}>
                        {record.risk}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 line-clamp-2">{record.description}</p>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Right Column: Comparison View */}
          <div className="lg:col-span-3">
            {selectedRecords.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 min-h-[400px] border border-dashed border-slate-800 rounded-xl bg-slate-900/20">
                <GitCompare className="h-12 w-12 mb-4 opacity-50" />
                <p>Select vulnerabilities from the left to begin comparing</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {selectedRecords.map(record => (
                  <motion.div 
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    key={record.id}
                    className="relative flex flex-col bg-slate-900 border border-slate-800 rounded-xl overflow-hidden"
                  >
                    <button 
                      onClick={() => toggleRecord(record)}
                      className="absolute top-3 right-3 text-slate-500 hover:text-white bg-slate-800 rounded-full p-1"
                    >
                      <X className="h-4 w-4" />
                    </button>
                    
                    <div className="p-5 border-b border-slate-800">
                      <h3 className="font-mono font-bold text-slate-200">{record.cve_id || `Record #${record.id}`}</h3>
                      <div className="mt-4 flex items-baseline justify-between">
                        <span className={`text-2xl font-black ${
                          record.risk === 'HIGH' ? 'text-red-500' :
                          record.risk === 'MEDIUM' ? 'text-orange-500' :
                          'text-emerald-500'
                        }`}>
                          {record.risk}
                        </span>
                        {record.cvss_predicted && (
                          <span className="text-sm font-semibold text-slate-400">
                            CVSS: <span className="text-white">{record.cvss_predicted.toFixed(1)}</span>
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="p-5 space-y-6 flex-grow">
                      <div>
                        <h4 className="text-xs uppercase tracking-wider text-slate-500 font-semibold mb-2">Description</h4>
                        <p className="text-sm text-slate-300 leading-relaxed line-clamp-6">{record.description}</p>
                      </div>

                      <div className="grid grid-cols-2 gap-4">
                        <div className="bg-slate-800/50 p-3 rounded-lg">
                          <span className="text-[10px] uppercase text-slate-500 block mb-1">Confidence</span>
                          <span className="text-lg font-mono text-white">{(record.confidence * 100).toFixed(1)}%</span>
                        </div>
                        <div className="bg-slate-800/50 p-3 rounded-lg">
                          <span className="text-[10px] uppercase text-slate-500 block mb-1">Anomaly</span>
                          <span className={`text-lg font-mono ${record.anomalous ? 'text-amber-500' : 'text-slate-300'}`}>
                            {record.anomalous ? 'DETECTED' : 'Normal'}
                          </span>
                        </div>
                      </div>

                      {record.explanation?.top_features && (
                        <div>
                          <h4 className="text-xs uppercase tracking-wider text-slate-500 font-semibold mb-2">Top Drivers</h4>
                          <div className="flex flex-wrap gap-2">
                            {record.explanation.top_features.slice(0, 3).map((f, i) => (
                              <span key={i} className="text-xs bg-slate-800 text-slate-300 px-2 py-1 rounded">
                                {f.term}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </motion.div>
                ))}
              </div>
            )}
          </div>

        </div>
      </div>
    </div>
  );
};

export default Compare;
