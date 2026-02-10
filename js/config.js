// API Configuration
// This file determines which backend URL to use based on the environment

// Backend URLs
const LOCAL_BACKEND_URL = 'http://localhost:3000';
const PRODUCTION_BACKEND_URL = 'https://my-project-gphv.onrender.com'; // Your live Render backend

// Environment detection
// Set to 'production' for live deployment, 'development' for local testing
const ENVIRONMENT = 'production'; // Force production mode to test Render backend

// Export the appropriate base URL
const API_BASE_URL = ENVIRONMENT === 'production' 
    ? PRODUCTION_BACKEND_URL 
    : LOCAL_BACKEND_URL;

// Export configuration
window.API_CONFIG = {
    baseURL: API_BASE_URL,
    apiURL: `${API_BASE_URL}/api`,
    healthURL: `${API_BASE_URL}/health`,
    environment: ENVIRONMENT
};

console.log(`🌐 MAIN config.js - Using ${ENVIRONMENT} environment`);
console.log(`🔗 Backend URL: ${API_BASE_URL}`);
console.log(`🔄 Cache bust: ${new Date().getTime()}`);



