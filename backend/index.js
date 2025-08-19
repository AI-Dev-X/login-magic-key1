const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const bodyParser = require('body-parser');
require('dotenv').config(); // Ensure environment variables are loaded at the very top

// Middleware de segurança
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');

// Logging
const morgan = require('morgan');
const logger = require('./utils/logger');

// Environment validation
const { validateEnvironment } = require('./utils/validateEnv');

// Validate environment variables before starting
try {
  validateEnvironment();
} catch (error) {
  console.error('❌ Environment validation failed:', error.message);
  process.exit(1);
}

// --- Route Imports ---
// It's good practice to group all your route imports together.
const authRoutes = require('./routes/authRoutes');
const paymentRoutes = require('./routes/paymentRoutes');
const { handleWebhook } = require('./routes/paymentRoutes');
const { handlePurchaseWebhook } = require('./routes/PurchasePyament');
const { handleMentorshipWebhook } = require('./routes/mentorshipPayments');
const bookingApprovalRoutes = require('./routes/bookingApprovalRoutes');
const mentorBookingRoutes = require('./routes/mentorBookingRoutes');
const courseRoutes = require('./routes/courseRoutes');
// const dashboardOptimized = require('./routes/dashboardOptimized'); // Replaced with cached version
const healthCheck = require('./routes/healthCheck');
// ... add other route imports here

// Validate environment variables before starting
validateEnvironment();

const app = express();

// --- 1. SECURITY MIDDLEWARE (ENHANCED) ---
// Importar sanitization middleware
const { sanitizationMiddleware, strictSanitization } = require('./middlewares/sanitization');
const { rateLimitConfig } = require('./utils/validators');

// Enhanced rate limiting with different tiers
const generalLimiter = rateLimit({
  ...rateLimitConfig.api,
  skip: (req) => req.path.includes('/health'), // Skip health check endpoints
});

const authLimiter = rateLimit(rateLimitConfig.autenticacao);
const oauthLimiter = rateLimit(rateLimitConfig.oauth); // Novo limiter para OAuth
const paymentLimiter = rateLimit(rateLimitConfig.pagamento);

// Apply general rate limiting
app.use(generalLimiter);

// Apply sanitization middleware globally
app.use(sanitizationMiddleware);

// Basic security headers
app.use(helmet());

// Compression middleware for better performance
app.use(compression());

// --- 2. CORE MIDDLEWARE SETUP ---
// Middleware should be configured before any routes that need it.
// The order here is important.

// Enable CORS for all routes and origins. This must come first.
// Dynamic CORS configuration based on environment
const allowedOrigins = process.env.ALLOWED_ORIGINS ? 
  process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) : 
  ["http://localhost:3000"];

app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));

// Trust proxy específico para Render.com (mais seguro)
if (process.env.NODE_ENV === 'production') {
  // Render.com usa proxies específicos - configuração mais segura
  app.set('trust proxy', 1); // Confia apenas no primeiro proxy
} else {
  // Desenvolvimento local
  app.set('trust proxy', false);
}

// Morgan HTTP request logging
const morganFormat = process.env.NODE_ENV === 'production' ? 'combined' : 'dev';
app.use(morgan(morganFormat, {
  stream: {
    write: (message) => logger.http(message.trim())
  }
}));

// --- 2. WEBHOOK ROUTES ---
// These routes require a raw body, so they use a specific bodyParser instance.
// They are placed before the general express.json() parser to avoid conflicts.
app.post(
  '/subscription/webhook',
  bodyParser.raw({ type: 'application/json' }),
  handleWebhook
);

app.post(
  '/coursePayment/webhook',
  bodyParser.raw({ type: 'application/json' }),
  handlePurchaseWebhook
);

app.post(
  '/mentorship/webhook',
  bodyParser.raw({ type: 'application/json' }),
  handleMentorshipWebhook
);

// --- 3. GENERAL MIDDLEWARE ---
// These parsers will apply to all subsequent routes.
app.use(express.json({ limit: '1mb' })); // Body parser for JSON payloads with limit
app.use(express.urlencoded({ extended: true, limit: '1mb' })); // Body parser for URL-encoded data with limit

// Express-session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (requires HTTPS)
    httpOnly: true,
    sameSite: 'lax' // Or 'none' if your frontend and backend are on different domains
  }
}));

// Passport Configuration
app.use(passport.initialize());
app.use(passport.session());


// --- 4. API ROUTES WITH ENHANCED SECURITY ---
// Apply OAuth rate limiting specifically for Google auth routes
app.use('/api/auth/google', oauthLimiter);
app.use('/api/auth/callback/google', oauthLimiter);

// Apply strict rate limiting for other authentication routes
app.use('/api/auth', authLimiter, authRoutes);

// Apply payment rate limiting for financial routes
app.use('/api/payment', paymentLimiter, paymentRoutes);
app.use('/api/course-purchase', paymentLimiter, require('./routes/PurchasePyament'));
app.use('/api/mentorship-payments', paymentLimiter, require('./routes/mentorshipPayments'));
app.use('/api/ratings', require("./routes/ratingRoutes"));
app.use('/api/infographic', require("./routes/FlashcardInfographicRoutes"));
app.use('/api/flashcards-daily', require("./routes/dailyFlashcardsChallenge"));
app.use('/api/simulation', require("./routes/simulationRoutes"));
app.use('/api/challenge', require("./routes/challengeRoutes"));
app.use('/api/reviews', require("./routes/reviewRoutes"));
app.use('/api/ai-explain', require("./routes/aiquestionfeedback"));
app.use('/api/mentor', require("./routes/mentorRoutes"));
app.use('/api/dashboard', require("./routes/dashboardRoutes"));
app.use('/api/courses', courseRoutes); // Use imported courseRoutes
app.use('/api/booking', require("./routes/bookingRoutes"));
app.use('/api/inquiries', require("./routes/inquiriesRoutes"));
app.use('/api/badges', require("./routes/badgeRoutes"));
app.use('/api/user-badges', require("./routes/userBadgeRoutes"));
app.use('/api/leader-board', require("./routes/leaderboardRoutes"));
app.use("/api/bookings", bookingApprovalRoutes); // Use imported bookingApprovalRoutes
app.use("/api/booking", mentorBookingRoutes); // Use imported mentorBookingRoutes
app.use('/api/user-stats', require("./routes/userStatsRoutes"));
app.use('/api/exam-type', require("./routes/examTypeRoutes"));
app.use('/api/quest', require("./routes/questRoutes"));
app.use('/api/v2', require("./routes/flashcardRouts"));
app.use('/api/referrals/admin', require("./routes/refferalAdminRoutes"));
app.use('/api/payment', paymentRoutes); // Use imported paymentRoutes
app.use('/api/refferal', require("./routes/referralRoutes"));
app.use('/api/test', require("./routes/test")); // Refactored into modular structure
app.use('/api/performanceTracking', require("./routes/performanceTrackingRoutes"));
app.use('/api/ai-planner', require("./routes/aiStudyPlanRoute"));
app.use('/api/course-purchase', require("./routes/PurchasePyament"));
app.use('/api/mentorship-payments', require("./routes/mentorshipPayments"));
app.use('/api/test/upload-questions', require("./routes/csvRoute"));

// --- NEW OPTIMIZED ROUTES ---
app.use('/api/dashboard', require('./routes/dashboardOptimizedWithCache')); // Optimized dashboard with cache
app.use('/api/health', healthCheck); // Health checks

// --- ENHANCED ERROR HANDLING MIDDLEWARE ---
const { globalErrorHandler, handleNotFound } = require('./middlewares/errorHandler');

// 404 handler for unmatched routes
app.use('*', handleNotFound);

// Global error handling middleware (must be last)
app.use(globalErrorHandler);

// --- 5. SERVER AND DATABASE INITIALIZATION ---
const PORT = process.env.PORT || 5000;

// Conexão com banco de dados with retry logic
const connectDB = async () => {
  const maxRetries = 5;
  let retries = 0;

  while (retries < maxRetries) {
    try {
      await mongoose.connect(process.env.MONGODB_URI, {
        serverSelectionTimeoutMS: 5000,
        heartbeatFrequencyMS: 10000,
        maxPoolSize: 10,
        minPoolSize: 2,
        maxIdleTimeMS: 30000,
      });
      console.log('✅ Database connected successfully');
      break;
    } catch (err) {
      retries++;
      console.error(`❌ Database connection attempt ${retries} failed:`, err.message);
      
      if (retries === maxRetries) {
        console.error('❌ Max database connection retries reached. Exiting...');
        process.exit(1);
      }
      
      // Wait before retrying (exponential backoff)
      const delay = Math.min(1000 * Math.pow(2, retries), 30000);
      console.log(`⏳ Retrying in ${delay / 1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
};

// Handle MongoDB connection events
mongoose.connection.on('connected', () => {
  console.log('📡 MongoDB connected');
});

mongoose.connection.on('disconnected', () => {
  console.log('📡 MongoDB disconnected');
});

mongoose.connection.on('error', (err) => {
  console.error('📡 MongoDB error:', err);
});

// Global error handlers
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Connect to database
connectDB();

// Start server
const server = app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('💤 Process terminated');
  });
});
