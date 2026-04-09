const request = require('supertest');
const app = require('./service.js');
const { DB } = require('./database/database.js');

// Test accounts
let testUser = { name: 'pizza diner', email: 'reg@test.com', password: 'a' };
const adminUser = { name: '常用名字', email: 'admin@jwt.com', password: 'admin-pizza' };

let testUserAuthToken = null;
let loginUserAuthToken = null;
let adminAuthToken = null;


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
        testUser = { name: 'updated pizza diner', email: 'reg@test.com', password: 'a' };
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

    test('list users with no authToken', async () => {
        const listUsersRes = await request(app).get('/api/user');
        expect(listUsersRes.status).toBe(401);
    });

    test('list users not as an admin', async () => {
        const [, userToken] = await registerUser(request(app));
        const listUsersRes = await request(app)
        .get('/api/user')
        .set('Authorization', 'Bearer ' + userToken);
        expect(listUsersRes.status).toBe(401);
    });

    test('list users as admin', async () => {
        const listUsersRes = await request(app)
        .get('/api/user')
        .set('Authorization', 'Bearer ' + adminAuthToken);
        expect(listUsersRes.status).toBe(200);
        expect(listUsersRes.body).toHaveProperty('users');
        expect(Array.isArray(listUsersRes.body.users)).toBe(true);
        expect(listUsersRes.body.users.length).toBeGreaterThan(0);
    });

    test('list users with pagination', async () => {
        const listUsersRes = await request(app)
        .get('/api/user?page=1&limit=5')
        .set('Authorization', 'Bearer ' + adminAuthToken);
        expect(listUsersRes.status).toBe(200);
        expect(listUsersRes.body).toHaveProperty('users');
        expect(Array.isArray(listUsersRes.body.users)).toBe(true);
    });

    test('list users with name filter', async () => {
        const listUsersRes = await request(app)
        .get('/api/user?page=0&limit=10&name=' + testUser.name)
        .set('Authorization', 'Bearer ' + adminAuthToken);
        expect(listUsersRes.status).toBe(200);
        expect(listUsersRes.body).toHaveProperty('users');
        expect(Array.isArray(listUsersRes.body.users)).toBe(true);
    });

    test('list users with offset doesnt have admin', async () => {
        const listUsersRes = await request(app)
        .get('/api/user?page=1&limit=5')
        .set('Authorization', 'Bearer ' + adminAuthToken);
        expect(listUsersRes.status).toBe(200);
        expect(listUsersRes.body).toHaveProperty('users');
        expect(Array.isArray(listUsersRes.body.users)).toBe(true);
        expect(listUsersRes.body.users.some(user => user.roles.some(role => role.role === 'admin'))).toBe(false);
    });

async function registerUser(service) {
  const testUser = {
    name: 'pizza diner',
    email: `${randomName()}@test.com`,
    password: 'a',
  };
  const registerRes = await service.post('/api/auth').send(testUser);
  registerRes.body.user.password = testUser.password;

  return [registerRes.body.user, registerRes.body.token];
}

function randomName() {
  return Math.random().toString(36).substring(2, 12);
}

test('delete user with no authToken', async () => {
    const deleteRes = await request(app).delete('/api/user/' + 1);
    expect(deleteRes.status).toBe(401);
});

test('delete user not as an admin', async () => {
    const [, userToken] = await registerUser(request(app));
    const deleteRes = await request(app)
    .delete('/api/user/' + 1)
    .set('Authorization', 'Bearer ' + userToken);
    expect(deleteRes.status).toBe(401);
});

test('delete user as admin', async () => {
    const [user] = await registerUser(request(app));
    const deleteRes = await request(app)
    .delete('/api/user/' + user.id)
    .set('Authorization', 'Bearer ' + adminAuthToken);
    expect(deleteRes.status).toBe(200);
    expect(deleteRes.body.message).toBe('user deleted');
});

test('delete non-existent user as admin', async () => {
    const deleteRes = await request(app)
    .delete('/api/user/9999')
    .set('Authorization', 'Bearer ' + adminAuthToken);
    expect(deleteRes.status).toBe(200);
});
});