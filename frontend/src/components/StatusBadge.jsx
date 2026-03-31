import React from 'react';
import { useGlobal } from '../context/GlobalContext';

const StatusBadge = () => {
  const { modelsReady } = useGlobal();

  return (
    <div className="flex items-center space-x-2 bg-gray-800 px-3 py-1.5 rounded-full border border-gray-700">
      <div className={`w-2 h-2 rounded-full ${modelsReady ? 'bg-green-500 animate-[pulse_2s_cubic-bezier(0.4,0,0.6,1)_infinite]' : 'bg-red-500'}`}></div>
      <span className={`text-xs font-bold tracking-wider uppercase ${modelsReady ? 'text-green-400' : 'text-red-400'}`}>
        {modelsReady ? 'Models Ready' : 'Not Trained'}
      </span>
    </div>
  );
};

export default StatusBadge;
