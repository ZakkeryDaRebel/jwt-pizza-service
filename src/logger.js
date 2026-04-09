const config = require('./config');

class Logger {
  httpLogger = (req, res, next) => {
    let send = res.send;
    res.send = (resBody) => {
      const logData = {
        authorized: !!req.headers.authorization,
        path: req.originalUrl,
        method: req.method,
        statusCode: res.statusCode,
        reqBody: this.allowlistedBody(req.body),
        resBodySize: typeof resBody === 'string' ? resBody.length : JSON.stringify(resBody || '').length,
      };
      const level = this.statusToLogLevel(res.statusCode);
      this.log(level, 'http', logData);
      res.send = send;
      return res.send(resBody);
    };
    next();
  };

  async logQuery(query, params, fn) {
    try {
        const result = await fn();

        this.log('info', 'db', {
        query,
        paramsCount: Array.isArray(params) ? params.length : 0,
        resultCount: Array.isArray(result) ? result.length : 1,
        });

        return result;
    } catch (err) {
        this.log('error', 'db', {
        query,
        paramsCount: Array.isArray(params) ? params.length : 0,
        error: err.message,
        });
        throw err;
    }
  }

  async fetchWithLogging(url, options) {
  const start = Date.now();

  try {
        const response = await fetch(url, options);
        let responseBody = null;
        try {
          responseBody = await response.clone().json();
        } catch {
          responseBody = null;
        }

        this.log('info', 'factory', {
        url,
        method: options.method,
        reqBody: options.body ? this.allowlistedBody(this.safeParse(options.body)) : null,
        status: response.status,
        resBodySize: responseBody ? JSON.stringify(responseBody).length : 0,
        latency: Date.now() - start,
        });

        return response;
    } catch (err) {
        this.log('error', 'factory', {
        url,
        method: options.method,
        error: err.message,
        });
        throw err;
    }
  }

  log(level, type, logData) {
    const labels = { component: config.logging.source, level: level, type: type };
    const values = [this.nowString(), this.sanitize(logData)];
    const logEvent = { streams: [{ stream: labels, values: [values] }] };

    this.sendLogToGrafana(logEvent);
  }

  statusToLogLevel(statusCode) {
    if (statusCode >= 500) return 'error';
    if (statusCode >= 400) return 'warn';
    return 'info';
  }

  nowString() {
    return (Math.floor(Date.now()) * 1000000).toString();
  }

  sanitize(logData) {
  const SENSITIVE_KEYS = ['password', 'token', 'authorization', 'jwt', 'apikey', 'secret', 'cookie', 'set-cookie', 'id', 'dinerid'];

  function deepSanitize(obj) {
    if (obj === null || obj === undefined) return obj;

    // Handle strings (including embedded JSON)
    if (typeof obj === 'string') {
      try {
        const parsed = JSON.parse(obj);
        return JSON.stringify(deepSanitize(parsed));
      } catch {
        // fallback regex cleanup for raw strings
        return obj
          .replace(/Bearer\s+[A-Za-z0-9.\-_]+/gi, 'Bearer *****')
          .replace(/"password":"[^"]*"/gi, '"password":"*****"')
          .replace(/"token":"[^"]*"/gi, '"token":"*****"')
          .replace(/"authorization":"[^"]*"/gi, '"authorization":"*****"');
      }
    }

    // Handle arrays
    if (Array.isArray(obj)) {
      return obj.map(deepSanitize);
    }

    // Handle objects
    if (typeof obj === 'object') {
      const sanitized = {};
      for (const key in obj) {
        const normalizedKey = key.toLowerCase().replace(/[_-]/g, '');
        if (SENSITIVE_KEYS.includes(normalizedKey)) {
          sanitized[key] = '*****';
        } else {
          sanitized[key] = deepSanitize(obj[key]);
        }
      }
      return sanitized;
    }

    return obj;
  }

  return JSON.stringify(deepSanitize(logData));
}

  safeParse(value) {
    if (!value || typeof value !== 'string') {
      return null;
    }
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  }

  allowlistedBody(body) {
    if (!body || typeof body !== 'object') {
      return null;
    }
    const allowedKeys = ['name', 'email', 'title', 'description', 'price', 'franchiseId', 'storeId', 'items'];
    const sanitizedBody = {};
    for (const key of allowedKeys) {
      if (Object.prototype.hasOwnProperty.call(body, key)) {
        sanitizedBody[key] = body[key];
      }
    }
    return sanitizedBody;
  }

  sendLogToGrafana(event) {
    const body = JSON.stringify(event);
    fetch(`${config.logging.endpointUrl}`, {
      method: 'post',
      body: body,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${config.logging.accountId}:${config.logging.apiKey}`,
      },
    }).then((res) => {
      if (!res.ok) console.log('Failed to send log to Grafana');
    }).catch(() => {});
  }
}
module.exports = new Logger();