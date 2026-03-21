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
        reqBody: req.body,
        resBody: resBody,
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
        params,
        resultCount: Array.isArray(result) ? result.length : 1,
        });

        return result;
    } catch (err) {
        this.log('error', 'db', {
        query,
        params,
        error: err.message,
        });
        throw err;
    }
  }

  async fetchWithLogging(url, options) {
  const start = Date.now();

  try {
        const response = await fetch(url, options);
        const body = await response.clone().json();

        this.log('info', 'factory', {
        url,
        method: options.method,
        reqBody: options.body ? JSON.parse(options.body) : null,
        status: response.status,
        resBody: body,
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

  sanitize(data) {
  const SENSITIVE_KEYS = ['password', 'token', 'authorization', 'jwt', 'apiKey', 'id'];

  function sanitizeValue(value) {
    if (typeof value === 'string') {
      // Try to parse nested JSON strings (like your resBody)
      try {
        const parsed = JSON.parse(value);
        return sanitizeValue(parsed);
      } catch {
        // Mask bearer tokens in plain strings
        return value.replace(/Bearer\s+[A-Za-z0-9.\-_]+/gi, 'Bearer *****');
      }
    }

    if (Array.isArray(value)) {
      return value.map(sanitizeValue);
    }

    if (value && typeof value === 'object') {
      const newObj = {};
      for (const key in value) {
        if (SENSITIVE_KEYS.includes(key.toLowerCase())) {
          newObj[key] = '*****';
        } else {
          newObj[key] = sanitizeValue(value[key]);
        }
      }
      return newObj;
    }

    return value;
  }

  const sanitized = sanitizeValue(data);
  return JSON.stringify(sanitized);
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
    });
  }
}
module.exports = new Logger();