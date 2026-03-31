import React, { createContext, useState, useContext, useEffect } from 'react';
import client from '../api/client';

const GlobalContext = createContext();

export const GlobalProvider = ({ children }) => {
  const [modelsReady, setModelsReady] = useState(false);
  const [historyRefreshTrigger, setHistoryRefreshTrigger] = useState(0);

  const checkHealth = async () => {
    try {
      const res = await client.get('/api/health');
      // Support both field names for compatibility
      setModelsReady(res.data.data.models_ready || res.data.data.models_trained || false);
    } catch (e) {
      setModelsReady(false);
    }
  };

  useEffect(() => {
    checkHealth();
  }, []);

  const triggerHistoryRefresh = () => {
    setHistoryRefreshTrigger(prev => prev + 1);
  };

  return (
    <GlobalContext.Provider value={{ modelsReady, historyRefreshTrigger, triggerHistoryRefresh, checkHealth }}>
      {children}
    </GlobalContext.Provider>
  );
};

export const useGlobal = () => useContext(GlobalContext);
