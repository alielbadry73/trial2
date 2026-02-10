# Backend Deployment Guide for IG Nation

## 🚀 Quick Deployment Options

### Option 1: Railway (Recommended)
1. **Create Railway Account**: https://railway.app
2. **Connect GitHub**: Link your repository to Railway
3. **Deploy Backend**:
   ```bash
   cd backend
   railway up
   ```
4. **Get Your URL**: Railway will give you a URL like `https://your-app-name.railway.app`
5. **Update Config**: Replace `https://your-backend-url.railway.app` in `js/config.js`

### Option 2: Render
1. **Create Render Account**: https://render.com
2. **New Web Service**: Choose "Node.js"
3. **Connect GitHub**: Link your repository
4. **Configure**:
   - Build Command: `npm install && npm start`
   - Start Command: `npm start`
5. **Deploy**: Your backend will be live at `https://your-app.onrender.com`

### Option 3: Heroku
1. **Install Heroku CLI**: `npm install -g heroku`
2. **Login**: `heroku login`
3. **Create App**: `heroku create your-app-name`
4. **Deploy**:
   ```bash
   cd backend
   heroku create
   git add .
   git commit -m "Deploy to Heroku"
   git push heroku main
   ```

## 🔧 Backend Setup Requirements

### Essential Files Needed:
```
backend/
├── package.json
├── server.js (or index.js)
├── .env
├── routes/
│   ├── auth.js
│   ├── courses.js
│   └── users.js
└── models/
    ├── User.js
    └── Course.js
```

### Package.json Example:
```json
{
  "name": "ig-nation-backend",
  "version": "1.0.0",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "dotenv": "^16.0.3",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.0",
    "sqlite3": "^5.1.6"
  }
}
```

### Basic Server.js Example:
```javascript
const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/courses', require('./routes/courses'));
app.use('/api/users', require('./routes/users'));

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Backend is running' });
});

app.listen(PORT, () => {
    console.log(`🚀 Backend running on port ${PORT}`);
});
```

## 🌐 Environment Variables

### Create `.env` file:
```env
NODE_ENV=production
PORT=3000
JWT_SECRET=your-super-secret-jwt-key
DB_PATH=./database.sqlite
```

## 🔄 Update Frontend Configuration

### After deployment, update `js/config.js`:
```javascript
const PRODUCTION_BACKEND_URL = 'https://your-actual-backend-url.railway.app';
```

## 🧪 Test Your Backend

### Health Check:
```bash
curl https://your-backend-url.railway.app/api/health
```

### Test Registration:
```bash
curl -X POST https://your-backend-url.railway.app/api/register \
  -H "Content-Type: application/json" \
  -d '{"first_name":"Test","last_name":"User","email":"test@example.com","password":"password123"}'
```

## 📋 Deployment Checklist

- [ ] Backend deployed to Railway/Render/Heroku
- [ ] Environment variables configured
- [ ] Database initialized
- [ ] Health check endpoint working
- [ ] CORS configured for your domain
- [ ] Frontend config updated with production URL
- [ ] Test registration/login flow
- [ ] Test course enrollment

## 🔍 Troubleshooting

### Common Issues:
1. **CORS Errors**: Make sure your backend allows requests from your Netlify domain
2. **Database Issues**: Check if SQLite file path is correct
3. **Environment Variables**: Ensure all required env vars are set
4. **Port Issues**: Make sure backend listens on PORT from env var

### CORS Configuration:
```javascript
const corsOptions = {
    origin: ['https://your-site.netlify.app', 'http://localhost:3000'],
    credentials: true
};
app.use(cors(corsOptions));
```

## 🎯 Next Steps

1. **Deploy your backend** using one of the options above
2. **Get your production URL**
3. **Update `js/config.js`** with your backend URL
4. **Deploy frontend changes** to Netlify
5. **Test the complete flow**

Your system will then work with a real backend instead of mock functions! 🚀
