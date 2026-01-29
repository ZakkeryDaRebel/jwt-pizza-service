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

    test('get user franchises', async () => {
        const res = await request(app).get('/api/franchise/1').set('Authorization', `Bearer ${testUserAuthToken}`).send();
        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
    });

    test('fail to create franchise as diner', async () => {
        const res = await request(app).post('/api/franchise').set('Authorization', `Bearer ${testUserAuthToken}`).send({ name: 'Test Franchise', admins: [ { email: testUser.email } ] });
        expect(res.status).toBe(403);
    })

    test('fail to create store as diner', async () => {
        const res = await request(app).post('/api/franchise/1/store').set('Authorization', `Bearer ${testUserAuthToken}`).send({ name: 'Test Location' });
        expect(res.status).toBe(403);
    });

    test('fail to delete store as diner', async () => {
        const res = await request(app).delete('/api/franchise/1/store/1').set('Authorization', `Bearer ${testUserAuthToken}`);
        expect(res.status).toBe(403);
    });

    test('fail to delete franchise as diner', async () => {
        const res = await request(app).delete('/api/franchise/1').set('Authorization', `Bearer ${testUserAuthToken}`);
        expect(res.status).toBe(403);
    })
});

describe('order tests', () => {
    let menuItem = null;

    test('get menu', async () => {
        const res = await request(app).get('/api/order/menu').send();
        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
        expect(res.body.length).toBeGreaterThan(0);
        menuItem = {
            menuId: res.body[0].id,
            title: res.body[0].title,
            image: res.body[0].image,
            description: res.body[0].description,
            price: res.body[0].price
        }
        console.log(menuItem);
    });

    test('fail to add menu item', async () => {
        const res = await request(app).put('/api/order/menu').send({ name: 'Test Pizza', description: 'A pizza for testing', price: 9.99  }).set('Authorization', `Bearer ${testUserAuthToken}`);
        expect(res.status).toBe(403);
    });

    test('get user orders', async () => {
        const res = await request(app).get('/api/order/').set('Authorization', `Bearer ${testUserAuthToken}`).send();
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('orders');
        expect(res.body.orders).toBeInstanceOf(Array);
    });

    test('order', async () => {
        const orderReq = { franchiseId: 1, storeId: 1, items: [ menuItem ] };
        const res = await request(app).post('/api/order/').set('Authorization', `Bearer ${testUserAuthToken}`).send(orderReq);
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('order');
        expect(res.body).toHaveProperty('jwt');
        expect(res.body.jwt).toMatch(/^[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*$/);
    });
});

describe('user tests', () => {
    let userID = null;
    test('get user', async () => {
        const res = await request(app).get('/api/user/me').set('Authorization', `Bearer ${testUserAuthToken}`).send();
        expect(res.status).toBe(200);
        const {...user } = { ...testUser, roles: [{ role: 'diner' }] };
        delete user.password;
        expect(res.body).toMatchObject(user);
        expect(res.body).toHaveProperty('id');
        expect(res.body.id).toBeGreaterThan(0);
        userID = res.body.id;
    });

    test('update user', async () => {
        const newName = 'updated pizza diner';
        const res = await request(app).put('/api/user/'+userID).set('Authorization', `Bearer ${testUserAuthToken}`).send({ name: newName, email: testUser.email, password: testUser.password });
        expect(res.status).toBe(200);
        expect(res.body.user.name).toBe(newName);
        expect(res.body.user.email).toBe(testUser.email);
        expect(res.body).toHaveProperty('token');
        expect(res.body.token).toMatch(/^[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*$/);
    });
});