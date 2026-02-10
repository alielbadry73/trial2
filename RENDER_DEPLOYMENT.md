# Render Deployment Guide for IG Nation Backend

## 🚀 Step-by-Step Render Deployment

### Step 1: Create Render Account
1. Go to https://render.com
2. Click "Sign Up" 
3. Sign up with GitHub (recommended) or email
4. Verify your email

### Step 2: Create Backend Repository
1. Make sure your backend code is in a GitHub repository
2. Your backend should have these files:
   ```
   backend/
   ├── package.json
   ├── server.js (or index.js)
   ├── .gitignore
   └── .env.example
   ```

### Step 3: Create New Web Service on Render
1. **Login to Render Dashboard**
2. Click **"New +"** button (top right)
3. Select **"Web Service"**

### Step 4: Connect Your Repository
1. **Choose "Connect a repository"**
2. **Select your GitHub account**
3. **Find your backend repository**
4. Click **"Connect"**

### Step 5: Configure Your Web Service

#### Basic Configuration:
- **Name**: `ig-nation-backend`
- **Region**: Choose closest to your users
- **Branch**: `main` (or your default branch)

#### Build Settings:
- **Runtime**: `Node`
- **Build Command**: `npm install`
- **Start Command**: `node server.js`

#### Advanced Settings:
- **Instance Type**: `Free` (to start) or `Standard` (for production)
- **Auto-Deploy**: ✅ Enabled (deploys on git push)

### Step 6: Add Environment Variables
1. Scroll down to **"Environment"** section
2. Add these variables:

#### Required Environment Variables:
```
NODE_ENV=production
PORT=3000
JWT_SECRET=your-super-secret-jwt-key-here
DATABASE_URL=sqlite:./database.sqlite
```

#### For SQLite Database:
```
DB_PATH=/opt/render/project/src/database.sqlite
```

#### For PostgreSQL (Recommended for production):
```
DATABASE_URL=postgresql://username:password@host:port/database
```

### Step 7: Create Database (if using PostgreSQL)
1. Go back to Render Dashboard
2. Click **"New +"**
3. Select **"PostgreSQL"**
4. Configure:
   - **Name**: `ig-nation-db`
   - **Database Name**: `ignation`
   - **User**: `ignation_user`
5. Click **"Create Database"**
6. Copy the connection string from database details
7. Add it to your web service environment variables

### Step 8: Deploy Your Backend
1. Click **"Create Web Service"**
2. Wait for deployment to complete (2-5 minutes)
3. Your backend will be available at: `https://ig-nation-backend.onrender.com`

### Step 9: Test Your Backend
Open your browser and test:
```
https://ig-nation-backend.onrender.com/api/health
```

Should return:
```json
{"status": "OK", "message": "Backend is running"}
```

## 🔧 Backend Code Requirements

### package.json Example:
```json
{
  "name": "ig-nation-backend",
  "version": "1.0.0",
  "description": "IG Nation Backend API",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "build": "echo 'No build step required'"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "dotenv": "^16.0.3",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.0",
    "sqlite3": "^5.1.6",
    "pg": "^8.8.0"
  },
  "engines": {
    "node": ">=14.0.0"
  }
}
```

### server.js Example:
```javascript
const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// CORS Configuration
const corsOptions = {
  origin: [
    'https://your-site.netlify.app',  // Your Netlify domain
    'http://localhost:3000',
    'https://localhost:3000'
  ],
  credentials: true
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Backend is running' });
});

// Import routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/users', require('./routes/users'));
app.use('/api/courses', require('./routes/courses'));

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV}`);
});
```

### .gitignore:
```
node_modules/
.env
database.sqlite
*.log
.DS_Store
```

## 🔄 Update Frontend Configuration

After deployment, update `js/config.js`:

```javascript
const PRODUCTION_BACKEND_URL = 'https://ig-nation-backend.onrender.com';
```

## 🧪 Test Complete API

### Test Registration:
```bash
curl -X POST https://ig-nation-backend.onrender.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Doe", 
    "email": "john@example.com",
    "password": "password123"
  }'
```

### Test Login:
```bash
curl -X POST https://ig-nation-backend.onrender.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "password123"
  }'
```

## 📋 Deployment Checklist

- [ ] Render account created
- [ ] Backend repository ready
- [ ] Web service created
- [ ] Environment variables set
- [ ] Database created (if using PostgreSQL)
- [ ] CORS configured for your domain
- [ ] Health endpoint working
- [ ] Registration/login tested
- [ ] Frontend config updated
- [ ] Complete flow tested

## 🔍 Common Issues & Solutions

### Issue: "Application Error"
- **Cause**: Missing start command or port issues
- **Fix**: Ensure `PORT=3000` in environment variables

### Issue: CORS Errors
- **Cause**: Frontend domain not allowed
- **Fix**: Add your Netlify domain to CORS origins

### Issue: Database Connection Failed
- **Cause**: Wrong database URL or credentials
- **Fix**: Check DATABASE_URL environment variable

### Issue: "Module Not Found"
- **Cause**: Missing dependencies
- **Fix**: Check package.json dependencies

## 🎯 Next Steps

1. **Deploy backend** on Render
2. **Get your URL**: `https://your-app.onrender.com`
3. **Update frontend config** with your Render URL
4. **Push changes** to Netlify
5. **Test complete flow** from registration to enrollment

## 🚀 Your Backend URLs

After deployment, you'll have:
- **API Base**: `https://ig-nation-backend.onrender.com`
- **Health Check**: `https://ig-nation-backend.onrender.com/api/health`
- **Register**: `https://ig-nation-backend.onrender.com/api/auth/register`
- **Login**: `https://ig-nation-backend.onrender.com/api/auth/login`

Your IG Nation platform will then work with a real backend! 🎉
