// API Configuration for Backend Public Files
// This file determines which backend URL to use based on the environment

// Fly.io deployment URL - Your live Fly.io backend
const RAILWAY_BACKEND_URL = 'https://ig-nation-app.fly.dev';

// Local development URL
const LOCAL_BACKEND_URL = 'http://localhost:8080';

// Determine which URL to use
// Set this to 'production' when deploying, or 'development' for local testing
const ENVIRONMENT = 'production'; // Force production mode for Fly.io backend

// Export the appropriate base URL
const API_BASE_URL = ENVIRONMENT === 'production' 
    ? RAILWAY_BACKEND_URL 
    : LOCAL_BACKEND_URL;

// Export configuration
window.API_CONFIG = {
    baseURL: API_BASE_URL,
    apiURL: `${API_BASE_URL}/api`,
    environment: ENVIRONMENT
};

console.log(`🌐 BACKEND config.js - Using ${ENVIRONMENT} environment`);
console.log(`🔗 Backend URL: ${API_BASE_URL}`);



