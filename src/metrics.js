const config = require('./config');
const os = require('os');

//
//HTTP Metrics
//
const requests = {};

// Middleware to track requests
function requestTracker(req, res, next) {
    console.log(req);
    console.log(res);
  const method = req.method;
  requests[method] = (requests[method] || 0) + 1;

  //If the user has an id, and has sent a backend request,
  //  then it is considered an active user
  if (req.user && (req.user.id || req.user.userId)) {
    recordUserActivity(req.user.id || req.user.userId);
  }

  next();
}

//
//Pizza Metrics
//
let pizzasSold = 0;
let revenue = 0;
let successfulOrders = 0;
let failedOrders = 0;
let orderLatency = 0;
let orderCount = 0;

function pizzaPurchase(success, latency, amount, price) {
  orderLatency += latency;
  orderCount++;

  if (success) {
    successfulOrders++;
    pizzasSold += amount;
    revenue += price;
  } else {
    failedOrders++;
  }
}

//
//Auth metrics
//
let authSuccess = 0;
let authFailure = 0;

function authAttempt(success) {
  if (success) {
    authSuccess++;
  } else {
    authFailure++;
  }
}

//
//CPU & Memory Metrics
//
function getCpuUsagePercentage() {
  const cpuUsage = os.loadavg()[0] / os.cpus().length;
  return cpuUsage.toFixed(2) * 100;
}

function getMemoryUsagePercentage() {
  const totalMemory = os.totalmem();
  const freeMemory = os.freemem();
  const usedMemory = totalMemory - freeMemory;
  const memoryUsage = (usedMemory / totalMemory) * 100;
  return memoryUsage.toFixed(2);
}

//
//Active users Metrics
//
const activeUsers = new Map();
const activityQueue = [];
const minutesInMS = 60 * 1000;
const activeTime = 15 * minutesInMS; 

function recordUserActivity(userId) {
    if (!userId) return;

    const now = Date.now();

    activeUsers.set(userId, now);
    activityQueue.push({ userId, time: now });
}

function userLoggedOut(userId) {
    if (!userId) return;
    activeUsers.delete(userId);
}

function cleanupInactiveUsers() {
    let queueIndex = 0;
    const now = Date.now();

    while (queueIndex < activityQueue.length) {
        const event = activityQueue[queueIndex];

        if (now - event.time <= activeTime) {
            break; //remaning events are all recent
        }

        //only remove the user if this was their last activity
        const lastActivity = activeUsers.get(event.userId);
        if (lastActivity === event.time) {
            activeUsers.delete(event.userId);
        }
        queueIndex++;
    }

    if (queueIndex > 0) {
        activityQueue.splice(0, queueIndex);
    }
}

//
//Send Metrics
//
// This will periodically send metrics to Grafana
if (process.env.NODE_ENV !== 'test') {
    setInterval(() => {
    const metrics = [];

    //HTTP Metrics
    Object.keys(requests).forEach((method) => {
        metrics.push(createMetric('requests', requests[method], '1', 'sum', 'asInt', { method }));
    });

    //Pizza Metrics
    metrics.push(createMetric('pizzaSold', pizzasSold, '1', 'sum', 'asInt', {}));
    metrics.push(createMetric('pizzaRevenue', revenue, 'usd', 'sum', 'asDouble', {}));
    metrics.push(createMetric('pizzaOrdersSuccess', successfulOrders, '1', 'sum', 'asInt', {}));
    metrics.push(createMetric('pizzaOrdersFailed', failedOrders, '1', 'sum', 'asInt', {}));
    metrics.push(createMetric('pizzaOrderLatency', orderLatency / (orderCount || 1), 'ms', 'gauge', 'asDouble', {}));

    //Auth Metrics
    metrics.push(createMetric('authSuccess', authSuccess, '1', 'sum', 'asInt', {}));
    metrics.push(createMetric('authFailure', authFailure, '1', 'sum', 'asInt', {}));

    //CPU & Memory Metrics
    metrics.push(createMetric('cpuUsage', getCpuUsagePercentage(), 'percent', 'gauge', 'asDouble', {}));
    metrics.push(createMetric('memoryUsage', getMemoryUsagePercentage(), 'percent', 'gauge', 'asDouble', {}));

    //Active users Metrics
    cleanupInactiveUsers();
    metrics.push(createMetric('activeUsers', activeUsers.size, '1', 'gauge', 'asInt', {}));

    //Send Metrics
    sendMetricToGrafana(metrics);
    }, 10000);
}

function createMetric(metricName, metricValue, metricUnit, metricType, valueType, attributes) {
  attributes = { ...attributes, source: config.source };

  const metric = {
    name: metricName,
    unit: metricUnit,
    [metricType]: {
      dataPoints: [
        {
          [valueType]: metricValue,
          timeUnixNano: Date.now() * 1000000,
          attributes: [],
        },
      ],
    },
  };

  Object.keys(attributes).forEach((key) => {
    metric[metricType].dataPoints[0].attributes.push({
      key: key,
      value: { stringValue: attributes[key] },
    });
  });

  if (metricType === 'sum') {
    metric[metricType].aggregationTemporality = 'AGGREGATION_TEMPORALITY_CUMULATIVE';
    metric[metricType].isMonotonic = true;
  }

  return metric;
}

function sendMetricToGrafana(metrics) {
  const body = {
    resourceMetrics: [
      {
        scopeMetrics: [
          {
            metrics,
          },
        ],
      },
    ],
  };

  fetch(`${config.endpointUrl}`, {
    method: 'POST',
    body: JSON.stringify(body),
    headers: { Authorization: `Bearer ${config.accountId}:${config.apiKey}`, 'Content-Type': 'application/json' },
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP status: ${response.status}`);
      }
    })
    .catch((error) => {
      console.error('Error pushing metrics:', error);
    });
}

module.exports = {
  requestTracker,
  pizzaPurchase,
  authAttempt,
  userLoggedOut,
  recordUserActivity,

  // expose internals for testing
  _test: {
    createMetric,
    recordUserActivity,
    cleanupInactiveUsers,
    getCpuUsagePercentage,
    getMemoryUsagePercentage,
    activeUsers,
    activityQueue,
    requests,
    get pizzasSold() { return pizzasSold; },
    get revenue() { return revenue; },
    get successfulOrders() { return successfulOrders; },
    get failedOrders() { return failedOrders; },
    get orderLatency() { return orderLatency; },
    get orderCount() { return orderCount; },
    get authSuccess() { return authSuccess; },
    get authFailure() { return authFailure; },
  },
};