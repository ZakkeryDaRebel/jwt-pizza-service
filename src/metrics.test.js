jest.mock('os', () => ({
  loadavg: () => [2],
  cpus: () => [1,2],
  totalmem: () => 100,
  freemem: () => 20
}));

const testMetrics = require('./metrics.js')._test;
const metrics = require('./metrics.js');

afterEach(() => {
  testMetrics.activeUsers.clear();
  testMetrics.activityQueue.length = 0;

  Object.keys(testMetrics.requests).forEach(k => delete testMetrics.requests[k]);
});

test('requestTracker increments request count', () => {
  const req = { method: 'GET', user: { id: 1 } };
  const res = {};
  const next = jest.fn();

  metrics.requestTracker(req, res, next);

  expect(next).toHaveBeenCalled();
  expect(testMetrics.activeUsers.has(1)).toBe(true);
});

test('requestTracker works without authenticated user', () => {
  const req = { method: 'POST' };
  const next = jest.fn();

  metrics.requestTracker(req, {}, next);

  expect(next).toHaveBeenCalled();
});

test('cpu usage calculation', () => {
  const cpu = testMetrics.getCpuUsagePercentage();
  expect(cpu).toBe(100);
});

global.fetch = jest.fn(() =>
  Promise.resolve({ ok: true })
);

test('recordUserActivity stores timestamp', () => {
  testMetrics.recordUserActivity(42);

  expect(testMetrics.activeUsers.has(42)).toBe(true);
  expect(testMetrics.activityQueue.length).toBe(1);
});

test('userLoggedOut removes user from activeUsers', () => {
  testMetrics.recordUserActivity(7);

  metrics.userLoggedOut(7);

  expect(testMetrics.activeUsers.has(7)).toBe(false);
});

test('cleanupInactiveUsers keeps recent users', () => {
  testMetrics.recordUserActivity(9);

  testMetrics.cleanupInactiveUsers();

  expect(testMetrics.activeUsers.has(9)).toBe(true);
});

test('memory usage calculation', () => {
  const mem = testMetrics.getMemoryUsagePercentage();
  expect(mem).toBe("80.00");
});

test('createMetric builds metric structure', () => {
  const metric = testMetrics.createMetric(
    'testMetric',
    5,
    '1',
    'sum',
    'asInt',
    { method: 'GET' }
  );

  expect(metric.name).toBe('testMetric');
  expect(metric.unit).toBe('1');
  expect(metric.sum.dataPoints[0].asInt).toBe(5);
  expect(metric.sum.dataPoints[0].attributes.length).toBeGreaterThan(0);
});

test('pizzaPurchase tracks successful order', () => {
  metrics.pizzaPurchase(true, 100, 3, 30);

  expect(testMetrics.successfulOrders).toBe(1);
  expect(testMetrics.pizzasSold).toBe(3);
  expect(testMetrics.revenue).toBe(30);
});

test('pizzaPurchase tracks failed order', () => {
  metrics.pizzaPurchase(false, 200, 1, 10);

  expect(testMetrics.failedOrders).toBe(1);
});

test('authAttempt success increments counter', () => {
  metrics.authAttempt(true);

  expect(testMetrics.authSuccess).toBe(1);
});

test('authAttempt failure increments counter', () => {
  metrics.authAttempt(false);

  expect(testMetrics.authFailure).toBe(1);
});

test('recordUserActivity ignores missing userId', () => {
  testMetrics.recordUserActivity(null);

  expect(testMetrics.activeUsers.size).toBe(0);
});

test('userLoggedOut ignores missing id', () => {
  metrics.recordUserActivity(10);
    metrics.userLoggedOut(null);

  expect(testMetrics.activeUsers.size).toBe(1);
});

test('requestTracker tracks HTTP method counts', () => {
  const req = { method: 'PUT' };
  const next = jest.fn();

  metrics.requestTracker(req, {}, next);

  expect(testMetrics.requests.PUT).toBe(1);
});