const request = require('supertest');
const app = require('./service.js');

const testUser = { name: 'pizza diner', email: 'reg@test.com', password: 'a' };
let testUserAuthToken = null;
let loginUserAuthToken = null;

beforeAll(async () => {
  testUser.email = Math.random().toString(36).substring(2, 12) + '@test.com';
  const registerRes = await request(app).post('/api/auth').send(testUser);
  testUserAuthToken = registerRes.body.token;
});

describe('authRouter tests', () => {
    test('login', async () => {
        const loginRes = await request(app).put('/api/auth').send(testUser);
        expect(loginRes.status).toBe(200);
        expect(loginRes.body.token).toMatch(/^[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*$/);
        loginUserAuthToken = loginRes.body.token;

        const {...user } = { ...testUser, roles: [{ role: 'diner' }] };
        delete user.password;
        expect(loginRes.body.user).toMatchObject(user);
        expect(loginRes.body.token).not.toBe(testUserAuthToken);
    });

    test('logout', async () => {
        const logoutRes = await request(app).delete('/api/auth').set('Authorization', `Bearer ${loginUserAuthToken}`);
        expect(logoutRes.status).toBe(200);
        expect(logoutRes.body.message).toBe('logout successful');
    });
});

describe('franchiseRouter tests', () => {
    test('list franchises', async () => {
        const res = await request(app).get('/api/franchise?page=0&limit=10&name=*').send();
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('franchises');
        expect(Array.isArray(res.body.franchises)).toBe(true);
        expect(res.body).toHaveProperty('more');
        expect(typeof res.body.more).toBe('boolean');
    });
});
