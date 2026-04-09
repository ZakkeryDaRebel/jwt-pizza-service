const express = require('express');
const { authRouter, setAuthUser } = require('./routes/authRouter.js');
const orderRouter = require('./routes/orderRouter.js');
const franchiseRouter = require('./routes/franchiseRouter.js');
const userRouter = require('./routes/userRouter.js');
const version = require('./version.json');
const config = require('./config.js');
const metrics = require('./metrics.js');
const logger = require('./logger.js');

const app = express();
const requestCountsByIp = new Map();
const REQUEST_WINDOW_MS = 60 * 1000;
const REQUEST_MAX_PER_WINDOW = 200;
const allowedOrigins = (process.env.CORS_ALLOWLIST || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
app.use(express.json());
app.use((req, res, next) => {
  const now = Date.now();
  const key = req.ip || 'unknown';
  const entry = requestCountsByIp.get(key);

  if (!entry || now > entry.resetAt) {
    requestCountsByIp.set(key, { count: 1, resetAt: now + REQUEST_WINDOW_MS });
    return next();
  }

  if (entry.count >= REQUEST_MAX_PER_WINDOW) {
    return res.status(429).json({ message: 'too many requests' });
  }

  entry.count += 1;
  requestCountsByIp.set(key, entry);
  return next();
});
app.use(setAuthUser);
app.use(metrics.requestTracker);
app.use(logger.httpLogger);
app.use((req, res, next) => {
  const requestOrigin = req.headers.origin;
  const allowAnyOrigin = allowedOrigins.length === 0;
  const isAllowedOrigin = allowAnyOrigin || (requestOrigin && allowedOrigins.includes(requestOrigin));
  if (isAllowedOrigin) {
    res.setHeader('Access-Control-Allow-Origin', requestOrigin || '*');
    if (requestOrigin && !allowAnyOrigin) {
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

const apiRouter = express.Router();
app.use('/api', apiRouter);
apiRouter.use('/auth', authRouter);
apiRouter.use('/user', userRouter);
apiRouter.use('/order', orderRouter);
apiRouter.use('/franchise', franchiseRouter);

apiRouter.use('/docs', (req, res) => {
  res.json({
    version: version.version,
    endpoints: [...authRouter.docs, ...userRouter.docs, ...orderRouter.docs, ...franchiseRouter.docs],
    config: { factory: config.factory.url, db: config.db.connection.host },
  });
});

app.get('/', (req, res) => {
  res.json({
    message: 'welcome to JWT Pizza',
    version: version.version,
  });
});

app.use('*', (req, res) => {
  res.status(404).json({
    message: 'unknown endpoint',
  });
});

// Default error handler for all exceptions and errors.
app.use((err, req, res, next) => {
  //console.error(err.message, err.stack)
  const requestId = req.headers['x-request-id'] || `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  logger.log('error', 'exception', {
    requestId,
    message: err.message,
    stack: err.stack,
    path: req?.originalUrl,
    method: req?.method,
  });

  const isProd = process.env.NODE_ENV === 'production';
  const clientError = { message: err.message || 'internal server error', requestId };
  if (!isProd) {
    clientError.details = err.stack;
  }
  res.status(err.statusCode ?? 500).json(clientError);
  next();
});

module.exports = app;
