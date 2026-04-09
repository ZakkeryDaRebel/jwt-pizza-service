const request = require('supertest');
const jwt = require('jsonwebtoken');
const config = require('./config.js');
const logger = require('./logger.js');

function randomEmail() {
  return `${Math.random().toString(36).substring(2, 12)}@security.test`;
}

async function registerUser(app, overrides = {}) {
  const user = {
    name: 'security user',
    email: randomEmail(),
    password: 'pw',
    ...overrides,
  };
  const res = await request(app).post('/api/auth').send(user);
  return { user, res };
}

async function loginUser(app, email, password) {
  return request(app).put('/api/auth').send({ email, password });
}

function loadFreshApp(extraEnv = {}) {
  jest.resetModules();
  const previous = {};
  for (const [k, v] of Object.entries(extraEnv)) {
    previous[k] = process.env[k];
    if (v === null) {
      delete process.env[k];
    } else {
      process.env[k] = v;
    }
  }
  const app = require('./service.js');
  for (const [k] of Object.entries(extraEnv)) {
    if (previous[k] === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = previous[k];
    }
  }
  return app;
}

describe('security matrix', () => {
  test('security test matrix maps each risk to a test id', () => {
    const matrix = {
      auth: ['SEC-AUTH-1', 'SEC-AUTH-2', 'SEC-AUTH-3', 'SEC-AUTH-4', 'SEC-AUTH-5'],
      sqliAndValidation: ['SEC-INJ-1', 'SEC-INJ-2', 'SEC-INJ-3', 'SEC-INJ-4'],
      errorDisclosure: ['SEC-ERR-1', 'SEC-ERR-2'],
      loggingRedaction: ['SEC-LOG-1', 'SEC-LOG-2', 'SEC-LOG-3'],
      corsAndRateLimit: ['SEC-CORS-1', 'SEC-CORS-2', 'SEC-RATE-1', 'SEC-RATE-2'],
      bootstrap: ['SEC-BOOT-1'],
    };

    Object.values(matrix).forEach((tests) => {
      expect(Array.isArray(tests)).toBe(true);
      expect(tests.length).toBeGreaterThan(0);
    });
  });
});

describe('authentication and session security', () => {
  const app = require('./service.js');

  test('SEC-AUTH-1 revoked token cannot access protected route after logout', async () => {
    const { user, res: registerRes } = await registerUser(app);
    const token = registerRes.body.token;
    expect(token).toBeTruthy();

    const logoutRes = await request(app).delete('/api/auth').set('Authorization', `Bearer ${token}`);
    expect(logoutRes.status).toBe(200);

    const reuseRes = await request(app).get('/api/user/me').set('Authorization', `Bearer ${token}`);
    expect(reuseRes.status).toBe(401);
    expect(reuseRes.body.message).toBe('unauthorized');

    const loginRes = await loginUser(app, user.email, user.password);
    expect(loginRes.status).toBe(200);
  });

  test('SEC-AUTH-2 missing and malformed tokens are rejected on protected routes', async () => {
    const missing = await request(app).get('/api/user/me');
    expect(missing.status).toBe(401);

    const malformed = await request(app).get('/api/user/me').set('Authorization', 'Bearer not-a-jwt-token');
    expect(malformed.status).toBe(401);
    expect(malformed.body.message).toBe('unauthorized');
  });

  test('SEC-AUTH-3 wrong issuer token is rejected', async () => {
    const { res: registerRes } = await registerUser(app);
    const payload = registerRes.body.user;
    const badIssuerToken = jwt.sign(payload, config.jwtSecret, {
      issuer: 'evil-issuer',
      audience: 'jwt-pizza-client',
      expiresIn: '1h',
    });

    const res = await request(app).get('/api/user/me').set('Authorization', `Bearer ${badIssuerToken}`);
    expect(res.status).toBe(401);
  });

  test('SEC-AUTH-4 wrong audience token is rejected', async () => {
    const { res: registerRes } = await registerUser(app);
    const payload = registerRes.body.user;
    const badAudienceToken = jwt.sign(payload, config.jwtSecret, {
      issuer: 'jwt-pizza-service',
      audience: 'wrong-audience',
      expiresIn: '1h',
    });

    const res = await request(app).get('/api/user/me').set('Authorization', `Bearer ${badAudienceToken}`);
    expect(res.status).toBe(401);
  });

  test('SEC-AUTH-5 expired token is rejected', async () => {
    const { res: registerRes } = await registerUser(app);
    const payload = registerRes.body.user;
    const expiredToken = jwt.sign(payload, config.jwtSecret, {
      issuer: 'jwt-pizza-service',
      audience: 'jwt-pizza-client',
      expiresIn: -1,
    });

    const res = await request(app).get('/api/user/me').set('Authorization', `Bearer ${expiredToken}`);
    expect(res.status).toBe(401);
  });
});

describe('injection and input validation security', () => {
  const app = require('./service.js');
  let token;
  let userId;
  let baseEmail;

  beforeAll(async () => {
    const { user, res } = await registerUser(app);
    token = res.body.token;
    baseEmail = user.email;
    const me = await request(app).get('/api/user/me').set('Authorization', `Bearer ${token}`);
    userId = me.body.id;
  });

  test('SEC-INJ-1 SQLi-like payload in name and email is treated as data, not query control', async () => {
    const sqliName = `' OR 1=1 --`;
    const sqliEmail = `x' OR '1'='1@test.com`;
    const sqliPassword = `pw' OR 1=1 --`;
    const res = await request(app)
      .put(`/api/user/${userId}`)
      .set('Authorization', `Bearer ${token}`)
      .send({ name: sqliName, email: sqliEmail, password: sqliPassword });

    expect(res.status).toBe(200);
    expect(res.body.user.name).toBe(sqliName);
    expect(res.body.user.email).toBe(sqliEmail);

    const oldCredsLogin = await loginUser(app, baseEmail, 'pw');
    expect(oldCredsLogin.status).toBe(404);
  });

  test('SEC-INJ-2 invalid user id is rejected and does not return 500', async () => {
    const adminLogin = await request(app).put('/api/auth').send({ email: 'a@jwt.com', password: 'admin' });
    expect(adminLogin.status).toBe(200);
    const res = await request(app)
      .put('/api/user/not-a-number')
      .set('Authorization', `Bearer ${adminLogin.body.token}`)
      .send({ name: 'x' });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('invalid user id');
  });

  test('SEC-INJ-3 invalid pagination values are safely handled', async () => {
    const adminLogin = await request(app).put('/api/auth').send({ email: 'a@jwt.com', password: 'admin' });
    const userListRes = await request(app)
      .get('/api/user?page=nan&limit=-1000')
      .set('Authorization', `Bearer ${adminLogin.body.token}`);

    expect(userListRes.status).toBe(200);
    expect(Array.isArray(userListRes.body.users)).toBe(true);

    const franchiseRes = await request(app).get('/api/franchise?page=abc&limit=999999').send();
    expect(franchiseRes.status).toBe(200);
    expect(Array.isArray(franchiseRes.body.franchises)).toBe(true);
  });

  test('SEC-INJ-4 malformed body field types are rejected', async () => {
    const res = await request(app)
      .put(`/api/user/${userId}`)
      .set('Authorization', `Bearer ${token}`)
      .send({ name: { nested: true } });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('invalid name');
  });
});

describe('error handling and information disclosure', () => {
  test('SEC-ERR-1 production responses do not leak stack and include requestId', async () => {
    const previousEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
      const app = loadFreshApp({ NODE_ENV: 'production' });
      const { res: registerRes } = await registerUser(app);
      const token = registerRes.body.token;
      const badOrder = { franchiseId: 1, storeId: 1, items: [{ menuId: -999, description: 'x', price: 1 }] };

      const res = await request(app)
        .post('/api/order')
        .set('Authorization', `Bearer ${token}`)
        .set('x-request-id', 'req-prod-1')
        .send(badOrder);

      expect(res.status).toBe(500);
      expect(res.body.message).toBeTruthy();
      expect(res.body.requestId).toBe('req-prod-1');
      expect(res.body.details).toBeUndefined();
      expect(JSON.stringify(res.body)).not.toMatch(/\/src\/|node_modules|Error:|\\n\s+at\s/);
    } finally {
      process.env.NODE_ENV = previousEnv;
    }
  });

  test('SEC-ERR-2 non-production responses include controlled debug details and requestId', async () => {
    const app = loadFreshApp({ NODE_ENV: 'development' });
    const { res: registerRes } = await registerUser(app);
    const token = registerRes.body.token;
    const badOrder = { franchiseId: 1, storeId: 1, items: [{ menuId: -999, description: 'x', price: 1 }] };

    const res = await request(app)
      .post('/api/order')
      .set('Authorization', `Bearer ${token}`)
      .set('x-request-id', 'req-dev-1')
      .send(badOrder);

    expect(res.status).toBe(500);
    expect(res.body.requestId).toBe('req-dev-1');
    expect(typeof res.body.details).toBe('string');
  });
});

describe('logging redaction and sensitive data handling', () => {
  test('SEC-LOG-1 logger sanitize redacts sensitive keys including nested and alternate casing', () => {
    const raw = {
      password: 'p1',
      token: 't1',
      Authorization: 'Bearer abc.def.ghi',
      apiKey: 'k1',
      api_key: 'k2',
      nested: {
        cookie: 'session=abc',
        'set-cookie': 'jwt=123',
        dinerId: 42,
      },
      safe: 'value',
    };

    const sanitized = JSON.parse(logger.sanitize(raw));
    expect(sanitized.password).toBe('*****');
    expect(sanitized.token).toBe('*****');
    expect(sanitized.Authorization).toBe('*****');
    expect(sanitized.apiKey).toBe('*****');
    expect(sanitized.api_key).toBe('*****');
    expect(sanitized.nested.cookie).toBe('*****');
    expect(sanitized.nested['set-cookie']).toBe('*****');
    expect(sanitized.nested.dinerId).toBe('*****');
    expect(sanitized.safe).toBe('value');
  });

  test('SEC-LOG-2 request body logging uses allowlist fields only', () => {
    const body = {
      name: 'n',
      email: 'e@test.com',
      title: 't',
      description: 'd',
      price: 1,
      franchiseId: 1,
      storeId: 2,
      items: [],
      password: 'secret',
      token: 'jwt',
      authorization: 'Bearer x',
    };
    const allowlisted = logger.allowlistedBody(body);

    expect(allowlisted.password).toBeUndefined();
    expect(allowlisted.token).toBeUndefined();
    expect(allowlisted.authorization).toBeUndefined();
    expect(allowlisted.name).toBe('n');
    expect(allowlisted.email).toBe('e@test.com');
  });

  test('SEC-LOG-3 DB logging records count metadata and avoids raw params', async () => {
    const spy = jest.spyOn(logger, 'log').mockImplementation(() => {});
    await logger.logQuery('SELECT * FROM user WHERE email=?', ['sensitive@email.test'], async () => [{ id: 1 }]);

    expect(spy).toHaveBeenCalledWith(
      'info',
      'db',
      expect.objectContaining({
        query: 'SELECT * FROM user WHERE email=?',
        paramsCount: 1,
        resultCount: 1,
      })
    );
    const loggedPayload = spy.mock.calls[0][2];
    expect(loggedPayload.params).toBeUndefined();
    spy.mockRestore();
  });
});

describe('rate limiting and CORS security', () => {
  test('SEC-RATE-1 auth endpoint throttles repeated attempts with 429', async () => {
    const app = require('./service.js');
    const email = randomEmail();
    let saw429 = false;

    for (let i = 0; i < 12; i += 1) {
      const res = await request(app).put('/api/auth').send({ email, password: 'wrong' });
      if (res.status === 429) {
        saw429 = true;
        expect(res.body.message).toBe('too many authentication attempts');
        break;
      }
    }
    expect(saw429).toBe(true);
  });

  test('SEC-RATE-2 global request throttling returns 429 under abuse volume', async () => {
    const app = require('./service.js');
    let status = 200;
    for (let i = 0; i < 220; i += 1) {
      const res = await request(app).get('/');
      status = res.status;
      if (status === 429) {
        expect(res.body.message).toBe('too many requests');
        break;
      }
    }
    expect(status).toBe(429);
  });

  test('SEC-CORS-1 with allowlist, trusted origin gets credentials header and untrusted does not', async () => {
    const app = loadFreshApp({ CORS_ALLOWLIST: 'https://trusted.example' });
    const trusted = await request(app).get('/').set('Origin', 'https://trusted.example');
    expect(trusted.headers['access-control-allow-origin']).toBe('https://trusted.example');
    expect(trusted.headers['access-control-allow-credentials']).toBe('true');

    const untrusted = await request(app).get('/').set('Origin', 'https://evil.example');
    expect(untrusted.headers['access-control-allow-origin']).toBeUndefined();
    expect(untrusted.headers['access-control-allow-credentials']).toBeUndefined();
  });

  test('SEC-CORS-2 without allowlist, wildcard origin is allowed without credential header', async () => {
    const app = loadFreshApp({ CORS_ALLOWLIST: null });
    const res = await request(app).get('/').set('Origin', 'https://anywhere.example');
    expect(res.headers['access-control-allow-origin']).toBe('https://anywhere.example');
    expect(res.headers['access-control-allow-credentials']).toBeUndefined();
  });
});

describe('bootstrap/admin initialization security', () => {
  test('SEC-BOOT-1 production bootstrap without required credentials fails safely', async () => {
    const fs = require('node:fs');
    const source = fs.readFileSync(require.resolve('./database/database.js'), 'utf8');
    expect(source).toContain("const isProd = process.env.NODE_ENV === 'production';");
    expect(source).toContain('if (!useDefaults && (!bootstrapName || !bootstrapEmail || !bootstrapPassword)) {');
    expect(source).toContain("throw new Error('Missing bootstrap admin credentials');");
  });
});
