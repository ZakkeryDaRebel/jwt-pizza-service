const express = require('express');
const { asyncHandler } = require('../endpointHelper.js');
const { DB, Role } = require('../database/database.js');
const { authRouter, setAuth } = require('./authRouter.js');
const metrics = require('../metrics.js');

const userRouter = express.Router();
express.use(metrics.requestTracker);

userRouter.docs = [
  {
    method: 'GET',
    path: '/api/user?page=1&limit=10&name=*',
    requiresAuth: true,
    description: 'Gets a list of users',
    example: `curl -X GET localhost:3000/api/user -H 'Authorization: Bearer tttttt'`,
    response: {
      users: [
        {
          id: 1,
          name: '常用名字',
          email: 'a@jwt.com',
          roles: [{ role: 'admin' }],
        },
      ],
    },
  },
  {
    method: 'GET',
    path: '/api/user/me',
    requiresAuth: true,
    description: 'Get authenticated user',
    example: `curl -X GET localhost:3000/api/user/me -H 'Authorization: Bearer tttttt'`,
    response: { id: 1, name: '常用名字', email: 'a@jwt.com', roles: [{ role: 'admin' }] },
  },
  {
    method: 'PUT',
    path: '/api/user/:userId',
    requiresAuth: true,
    description: 'Update user',
    example: `curl -X PUT localhost:3000/api/user/1 -d '{"name":"常用名字", "email":"a@jwt.com", "password":"admin"}' -H 'Content-Type: application/json' -H 'Authorization: Bearer tttttt'`,
    response: { user: { id: 1, name: '常用名字', email: 'a@jwt.com', roles: [{ role: 'admin' }] }, token: 'tttttt' },
  },
];

/**
 * Method to get the current User. 
 * @returns the json of the user in the request
 */
userRouter.get(
  '/me',
  authRouter.authenticateToken,
  asyncHandler(async (req, res) => {
    res.json(req.user);
  })
);

/**
 * Method to update user. Makes sure the userID is a valid number, then checks to see if the user is an admin. If not an Admin, throws a 403 error. Otherwise, 
 *   updates the database with the request information (userID, name, email, and password), then calls setAuth() to login the user. 
 * @returns json of the updated User and the authToken. 
 * @throws 403 "Unauthorized"
 */
userRouter.put(
  '/:userId',
  authRouter.authenticateToken,
  asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;
    const userId = Number(req.params.userId);
    const user = req.user;
    if (user.id !== userId && !user.isRole(Role.Admin)) {
      return res.status(403).json({ message: 'unauthorized' });
    }

    const updatedUser = await DB.updateUser(userId, name, email, password);
    const auth = await setAuth(updatedUser);
    res.json({ user: updatedUser, token: auth });
  })
);

/**
 * Method to Delete a User. 
 * Will require the user to be an Admin, otherwise will throw a 401 unauthorized exception. Then it will use the userID from the request to delete the user from the 
 *   database.
 * @returns json of a message saying the user was deleted.
 * @throws 401 "Unauthorized"
 */
userRouter.delete(
  '/:userId',
  authRouter.authenticateToken,
  asyncHandler(async (req, res) => {
    if (!req.user.isRole(Role.Admin)) {
      return res.status(401).json({ message: 'unauthorized' });
    }
    const userId = Number(req.params.userId);
    await DB.deleteUser(userId);
    res.json({ message: 'user deleted' });
  })
);

/**
 * Method to List Users. 
 * Will require the user to be an Admin, otherwise will throw a 401 unauthorized exception. Then it will use the parameters to get a list of users from the database, 
 *   returning that list of users and a boolean of if there are more users to get.
 * @returns json of the list of users and boolean of it there are more users
 * @throws 401 "Unauthorized"
 */
userRouter.get(
  '/',
  authRouter.authenticateToken,
  asyncHandler(async (req, res) => {
    if (!req.user.isRole(Role.Admin)) {
      return res.status(401).json({ message: 'unauthorized' });
    }
    const [users, more] = await DB.getUsers(req.user, req.query.page, req.query.limit, req.query.name);
    res.json({users, more});
  })
);

module.exports = userRouter;
