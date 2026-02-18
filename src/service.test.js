const request = require('supertest');
const app = require('./service.js');
const { DB } = require('./database/database.js');

// Test accounts
const testUser = { name: 'pizza diner', email: 'reg@test.com', password: 'a' };
const adminUser = { name: '常用名字', email: 'a@jwt.com', password: 'admin' };

let testUserAuthToken = null;
let loginUserAuthToken = null;
let adminAuthToken = null;

const authHeader = (token) => ({ Authorization: `Bearer ${token}` });

beforeAll(async () => {
  // Ensure DB initialization completed in all environments (local & CI)
  await DB.initialized;

  // Register a fresh test user
  testUser.email = Math.random().toString(36).substring(2, 12) + '@test.com';
  const registerRes = await request(app).post('/api/auth').send(testUser);
  expect(registerRes.status).toBe(200);
  testUserAuthToken = registerRes.body.token;

  // Login admin (default admin seeded during DB init)
  const adminRes = await request(app).put('/api/auth').send({ email: adminUser.email, password: adminUser.password });
  expect(adminRes.status).toBe(200);
  adminAuthToken = adminRes.body.token;
});

describe('Auth - basic flows', () => {
  test('login returns token and user', async () => {
    const res = await request(app).put('/api/auth').send({ email: testUser.email, password: testUser.password });
    expect(res.status).toBe(200);
    expect(res.body.token).toMatch(/^[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*$/);
    loginUserAuthToken = res.body.token;

    const { ...user } = { ...testUser, roles: [{ role: 'diner' }] };
    delete user.password;
    expect(res.body.user).toMatchObject(user);
    expect(res.body.token).not.toBe(testUserAuthToken);
  });

  test('logout invalidates token', async () => {
    const logoutRes = await request(app).delete('/api/auth').set(authHeader(loginUserAuthToken));
    expect(logoutRes.status).toBe(200);
    expect(logoutRes.body).toHaveProperty('message', 'logout successful');

    // Using same token again should be unauthorized
    const again = await request(app).delete('/api/auth').set(authHeader(loginUserAuthToken));
    expect(again.status).toBe(401);
  });

  test('registration validation and failed login', async () => {
    const badReg = await request(app).post('/api/auth').send({ name: 'x' });
    expect(badReg.status).toBe(400);
    expect(badReg.body.message).toMatch(/name, email, and password/);

    const badLogin = await request(app).put('/api/auth').send({ email: testUser.email, password: 'wrongpassword' });
    expect(badLogin.status).toBe(404);
  });
});

describe('Franchise - permissions and admin flows', () => {
  test('listing franchises is public and paginated', async () => {
    const res = await request(app).get('/api/franchise?page=0&limit=10&name=*');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('franchises');
    expect(Array.isArray(res.body.franchises)).toBe(true);
    expect(res.body).toHaveProperty('more');
  });

  test('non-admin cannot create franchise or stores', async () => {
    const createRes = await request(app).post('/api/franchise').set(authHeader(testUserAuthToken)).send({ name: 'X', admins: [{ email: testUser.email }] });
    expect(createRes.status).toBe(403);

    const createStore = await request(app).post('/api/franchise/1/store').set(authHeader(testUserAuthToken)).send({ name: 'S' });
    expect(createStore.status).toBe(403);
  });

  test('admin can create and delete franchise and store', async () => {
    const franchiseReq = { name: 'Admin Test Franchise', admins: [{ email: testUser.email }] };
    const createFr = await request(app).post('/api/franchise').set(authHeader(adminAuthToken)).send(franchiseReq);
    expect(createFr.status).toBe(200);
    expect(createFr.body).toHaveProperty('id');
    const franchiseID = createFr.body.id;

    const createStore = await request(app).post(`/api/franchise/${franchiseID}/store`).set(authHeader(adminAuthToken)).send({ name: 'Admin Store' });
    expect(createStore.status).toBe(200);
    expect(createStore.body).toHaveProperty('id');

    const delStore = await request(app).delete(`/api/franchise/${franchiseID}/store/${createStore.body.id}`).set(authHeader(adminAuthToken));
    expect(delStore.status).toBe(200);

    const delFr = await request(app).delete(`/api/franchise/${franchiseID}`).set(authHeader(adminAuthToken));
    expect(delFr.status).toBe(200);
  });
});

describe('Order - menu and ordering', () => {
  test('menu is readable; adding requires admin', async () => {
    const menu = await request(app).get('/api/order/menu');
    expect(menu.status).toBe(200);
    expect(Array.isArray(menu.body)).toBe(true);

    const addByDiner = await request(app).put('/api/order/menu').set(authHeader(testUserAuthToken)).send({ title: 'X', description: 'x', image: 'i.png', price: 1.0 });
    expect(addByDiner.status).toBe(403);

    const addByAdmin = await request(app).put('/api/order/menu').set(authHeader(adminAuthToken)).send({ title: 'Admin Pizza', description: 'A', image: 'a.png', price: 2.0 });
    expect(addByAdmin.status).toBe(200);
    expect(Array.isArray(addByAdmin.body)).toBe(true);
  });

  test('orders require auth and invalid items produce server error', async () => {
    const unauth = await request(app).get('/api/order/');
    expect(unauth.status).toBe(401);

    const badOrder = { franchiseId: 1, storeId: 1, items: [{ menuId: -1, description: 'Bad', price: 0.01 }] };
    const res = await request(app).post('/api/order/').set(authHeader(testUserAuthToken)).send(badOrder);
    expect([500, 404]).toContain(res.status);
  });
});

describe('User - profile and updates', () => {
  let userID = null;

  test('get current user and update', async () => {
    const me = await request(app).get('/api/user/me').set(authHeader(testUserAuthToken));
    expect(me.status).toBe(200);
    const { ...user } = { ...testUser, roles: [{ role: 'diner' }] };
    delete user.password;
    expect(me.body).toMatchObject(user);
    expect(me.body.id).toBeGreaterThan(0);
    userID = me.body.id;

    const newName = 'updated pizza diner';
    const upd = await request(app).put(`/api/user/${userID}`).set(authHeader(testUserAuthToken)).send({ name: newName, email: testUser.email, password: testUser.password });
    expect(upd.status).toBe(200);
    expect(upd.body.user.name).toBe(newName);
    expect(upd.body).toHaveProperty('token');
  });

  test('protected user endpoints reject without auth', async () => {
    const noMe = await request(app).get('/api/user/me');
    expect(noMe.status).toBe(401);

    const noUpd = await request(app).put(`/api/user/${userID}`).send({ name: 'x' });
    expect(noUpd.status).toBe(401);
  });
});




beforeAll(async () => {
  // Wait for database initialization to complete
  await DB.initialized;
  
  testUser.email = Math.random().toString(36).substring(2, 12) + '@test.com';
  const registerRes = await request(app).post('/api/auth').send(testUser);
  testUserAuthToken = registerRes.body.token;

  const adminRes = await request(app).put('/api/auth').send(adminUser);
  adminAuthToken = adminRes.body.token;
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

    test('fail to register with missing fields', async () => {
        const res = await request(app).post('/api/auth').send({ name: 'Test User' });
        expect(res.status).toBe(400);
        expect(res.body.message).toBe('name, email, and password are required');
    });

    test('fail to login with wrong password', async () => {
        const res = await request(app).put('/api/auth').send({ email: testUser.email, password: 'wrongpassword' });
        expect(res.status).toBe(404);
    });

    test('fail to logout without auth token', async () => {
        const res = await request(app).delete('/api/auth');
        expect(res.status).toBe(401);
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

    test('list franchises with pagination', async () => {
        const res = await request(app).get('/api/franchise?page=1&limit=5').send();
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('franchises');
        expect(Array.isArray(res.body.franchises)).toBe(true);
    });

    test('list franchises with name filter', async () => {
        const res = await request(app).get('/api/franchise?page=0&limit=10&name=pizza').send();
        expect(res.status).toBe(200);
        expect(Array.isArray(res.body.franchises)).toBe(true);
    });

    test('fail to create franchise as diner', async () => {
        const res = await request(app).post('/api/franchise').set('Authorization', `Bearer ${testUserAuthToken}`).send({ name: 'Test Franchise', admins: [ { email: testUser.email } ] });
        expect(res.status).toBe(403);
    })

    test('fail to create franchise without auth', async () => {
        const res = await request(app).post('/api/franchise').send({ name: 'Test Franchise', admins: [ { email: testUser.email } ] });
        expect(res.status).toBe(401);
    })

    test('fail to create store as diner', async () => {
        const res = await request(app).post('/api/franchise/1/store').set('Authorization', `Bearer ${testUserAuthToken}`).send({ name: 'Test Location' });
        expect(res.status).toBe(403);
    });

    test('fail to create store without auth', async () => {
        const res = await request(app).post('/api/franchise/1/store').send({ name: 'Test Location' });
        expect(res.status).toBe(401);
    });

    test('fail to delete store as diner', async () => {
        const res = await request(app).delete('/api/franchise/1/store/1').set('Authorization', `Bearer ${testUserAuthToken}`);
        expect(res.status).toBe(403);
    });

    test('fail to delete store without auth', async () => {
        const res = await request(app).delete('/api/franchise/1/store/1');
        expect(res.status).toBe(401);
    });

    test('fail to delete franchise as diner', async () => {
        const res = await request(app).delete('/api/franchise/1').set('Authorization', `Bearer ${testUserAuthToken}`);
        expect(res.status).toBe(403);
    });

    let franchiseID = null;

    test('create franchise as admin', async () => {
        const franchiseReq = { name: 'Admin Test Franchise', admins: [{ email: adminUser.email }] };
        const res = await request(app).post('/api/franchise').set('Authorization', `Bearer ${adminAuthToken}`).send(franchiseReq);
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('id');
        franchiseID = res.body.id;
        expect(res.body.name).toBe(franchiseReq.name);
        expect(Array.isArray(res.body.admins)).toBe(true);
    });

    test('create store as admin', async () => {
        const res = await request(app).post(`/api/franchise/${franchiseID}/store`).set('Authorization', `Bearer ${adminAuthToken}`).send({ name: 'Admin Test Store' });
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('id');
        expect(res.body.name).toBe('Admin Test Store');
        expect(res.body).toHaveProperty('franchiseId');
    });

    test('delete store as admin', async () => {
        const res = await request(app).delete(`/api/franchise/${franchiseID}/store/1`).set('Authorization', `Bearer ${adminAuthToken}`);
        expect(res.status).toBe(200);
        expect(res.body.message).toBe('store deleted');
    });

    test('delete franchise as admin', async () => {
        const res = await request(app).delete(`/api/franchise/${franchiseID}`).set('Authorization', `Bearer ${adminAuthToken}`);
        expect(res.status).toBe(200);
        expect(res.body.message).toBe('franchise deleted');
    });
});

describe('order tests', () => {
    test('get menu', async () => {
        const res = await request(app).get('/api/order/menu').send();
        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
    });

    test('fail to add menu item', async () => {
        const res = await request(app).put('/api/order/menu').send({ name: 'Test Pizza', description: 'A pizza for testing', price: 9.99  }).set('Authorization', `Bearer ${testUserAuthToken}`);
        expect(res.status).toBe(403);
    });

    test('add menu item as admin', async () => {
        const menuItem = { title: 'Admin Pizza', description: 'A pizza for admin testing', image: 'pizza1.png', price: 12.99 };
        const res = await request(app).put('/api/order/menu').set('Authorization', `Bearer ${adminAuthToken}`).send(menuItem);
        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
        expect(res.body.some(item => item.title === 'Admin Pizza')).toBe(true);
    });

    test('fail to add menu item without auth', async () => {
        const res = await request(app).put('/api/order/menu').send({ title: 'Test', description: 'Test', image: 'test.png', price: 9.99 });
        expect(res.status).toBe(401);
    });

    test('get user orders', async () => {
        const res = await request(app).get('/api/order/').set('Authorization', `Bearer ${testUserAuthToken}`).send();
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('orders');
        expect(res.body.orders).toBeInstanceOf(Array);
    });

    test('get user orders with pagination', async () => {
        const res = await request(app).get('/api/order/?page=1').set('Authorization', `Bearer ${testUserAuthToken}`).send();
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('orders');
        expect(res.body).toHaveProperty('dinerId');
        expect(res.body).toHaveProperty('page');
    });

    test('order with invalid menu item', async () => {
        let menuItem = {
            menuId: -1,
            title: "Fake Pizza",
            image: "pizza1.png",
            description: "A pizza for testing",
            price: 9.99
        }
        const orderReq = { franchiseId: 1, storeId: 1, items: [ menuItem ] };
        const res = await request(app).post('/api/order/').set('Authorization', `Bearer ${testUserAuthToken}`).send(orderReq);
        expect(res.status).toBe(500);
    });

    test('fail to get orders without auth', async () => {
        const res = await request(app).get('/api/order/').send();
        expect(res.status).toBe(401);
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

    test('get fake user', async () => {
        const res = await request(app).get('/api/user/999').set('Authorization', `Bearer 1234`).send();
        expect(res.status).toBe(404);
    })

    test('update user', async () => {
        const newName = 'updated pizza diner';
        const res = await request(app).put('/api/user/'+userID).set('Authorization', `Bearer ${testUserAuthToken}`).send({ name: newName, email: testUser.email, password: testUser.password });
        expect(res.status).toBe(200);
        expect(res.body.user.name).toBe(newName);
        expect(res.body.user.email).toBe(testUser.email);
        expect(res.body).toHaveProperty('token');
        expect(res.body.token).toMatch(/^[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*$/);
    });

    test('fail to get user without auth', async () => {
        const res = await request(app).get('/api/user/me').send();
        expect(res.status).toBe(401);
    });

    test('fail to update user without auth', async () => {
        const res = await request(app).put('/api/user/' + userID).send({ name: 'Test' });
        expect(res.status).toBe(401);
    });
});