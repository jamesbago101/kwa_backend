# KWAI Portal Backend

Express.js backend API for KWAI Portal mobile application.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
npm start
```

For development with auto-reload:
```bash
npm run dev
```

## API Endpoints

### Authentication
- `POST /api/auth/login` - Login with email/student_id and password
- `POST /api/auth/set-password` - Create or update password

### Protected Routes (require authentication token)
- `GET /api/payments` - Get statement of account and payment history
- `GET /api/attendance` - Get attendance records
- `GET /api/notifications` - Get notifications

### Health Check
- `GET /api/health` - Check if server is running

## Database Connection

Connects to Railway MySQL database:
- Host: metro.proxy.rlwy.net
- Port: 16083
- Database: railway

## Environment Variables

Create a `.env` file with:
```
PORT=3000
JWT_SECRET=your_secret_key_here
NODE_ENV=development
```

