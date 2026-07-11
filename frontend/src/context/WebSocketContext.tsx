import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useToast } from '@/hooks/use-toast';
import { CVEItem } from '@/services/api';

interface WebSocketContextType {
  newHighRiskCount: number;
  clearCount: () => void;
  latestCve: CVEItem | null;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

export const WebSocketProvider = ({ children }: { children: ReactNode }) => {
  const [newHighRiskCount, setNewHighRiskCount] = useState(0);
  const [latestCve, setLatestCve] = useState<CVEItem | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    const wsUrl = 'ws://localhost:8000/ws/cve-feed';
    let ws: WebSocket;
    let reconnectTimeout: NodeJS.Timeout;

    const connect = () => {
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log('Connected to real-time CVE feed');
      };

      ws.onmessage = (event) => {
        try {
          const cve: CVEItem = JSON.parse(event.data);
          
          if (cve.risk === 'HIGH') {
            setNewHighRiskCount(prev => prev + 1);
            setLatestCve(cve);
            
            toast({
              title: `Critical Alert: ${cve.cve_id}`,
              description: `New HIGH risk vulnerability detected with ${(cve.confidence * 100).toFixed(0)}% confidence.`,
              variant: "destructive",
              duration: 8000,
            });
          }
        } catch (error) {
          console.error('Error parsing WS message:', error);
        }
      };

      ws.onclose = () => {
        console.log('Disconnected from real-time CVE feed. Reconnecting in 5s...');
        reconnectTimeout = setTimeout(connect, 5000);
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        ws.close(); // Force a close event to trigger reconnect
      };
    };

    connect();

    return () => {
      clearTimeout(reconnectTimeout);
      if (ws) {
        ws.onclose = null; // Prevent reconnect on intentional unmount
        ws.close();
      }
    };
  }, [toast]);

  const clearCount = () => setNewHighRiskCount(0);

  return (
    <WebSocketContext.Provider value={{ newHighRiskCount, clearCount, latestCve }}>
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  if (context === undefined) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};
