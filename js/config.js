// API Configuration
// This file determines which backend URL to use based on the environment

// Backend URLs
const LOCAL_BACKEND_URL = 'http://localhost:3000';
const PRODUCTION_BACKEND_URL = 'https://your-backend-url.railway.app'; // Replace with your actual Railway URL

// Environment detection
// Set to 'production' for live deployment, 'development' for local testing
const ENVIRONMENT = window.location.hostname.includes('localhost') || window.location.hostname.includes('127.0.0.1') 
    ? 'development' 
    : 'production';

// Export the appropriate base URL
const API_BASE_URL = ENVIRONMENT === 'production' 
    ? PRODUCTION_BACKEND_URL 
    : LOCAL_BACKEND_URL;

// Export configuration
window.API_CONFIG = {
    baseURL: API_BASE_URL,
    apiURL: `${API_BASE_URL}/api`,
    environment: ENVIRONMENT
};

console.log(`🌐 API Configuration: Using ${ENVIRONMENT} environment`);
console.log(`🔗 Backend URL: ${API_BASE_URL}`);



