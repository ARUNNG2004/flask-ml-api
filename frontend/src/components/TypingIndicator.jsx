import React from 'react';

const TypingIndicator = () => {
  return (
    <div className="flex space-x-1.5 p-3 px-4 bg-gray-800 rounded-2xl rounded-tl-sm w-fit items-center h-10 border border-gray-700 shadow-sm">
      <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
      <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
      <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
    </div>
  );
};

export default TypingIndicator;
