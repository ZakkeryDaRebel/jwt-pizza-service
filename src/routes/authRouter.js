const express = require('express');
const jwt = require('jsonwebtoken');
const config = require('../config.js');
const { asyncHandler } = require('../endpointHelper.js');
const { DB, Role } = require('../database/database.js');

const authRouter = express.Router();

authRouter.docs = [
  {
    method: 'POST',
    path: '/api/auth',
    description: 'Register a new user',
    example: `curl -X POST localhost:3000/api/auth -d '{"name":"pizza diner", "email":"d@jwt.com", "password":"diner"}' -H 'Content-Type: application/json'`,
    response: { user: { id: 2, name: 'pizza diner', email: 'd@jwt.com', roles: [{ role: 'diner' }] }, token: 'tttttt' },
  },
  {
    method: 'PUT',
    path: '/api/auth',
    description: 'Login existing user',
    example: `curl -X PUT localhost:3000/api/auth -d '{"email":"a@jwt.com", "password":"admin"}' -H 'Content-Type: application/json'`,
    response: { user: { id: 1, name: '常用名字', email: 'a@jwt.com', roles: [{ role: 'admin' }] }, token: 'tttttt' },
  },
  {
    method: 'DELETE',
    path: '/api/auth',
    requiresAuth: true,
    description: 'Logout a user',
    example: `curl -X DELETE localhost:3000/api/auth -H 'Authorization: Bearer tttttt'`,
    response: { message: 'logout successful' },
  },
];

/**
 * If there is an authToken, checks to see if it is valid by trying to get a userID connected to the 
 *   authToken from the database. Then calls the `next` parameter as a function
 * @param {*} req request
 * @param {*} res response
 * @param {*} next function to be called at the end
 */
async function setAuthUser(req, res, next) {
  const token = readAuthToken(req);
  if (token) {
    try {
      if (await DB.isLoggedIn(token)) {
        // Check the database to make sure the token is valid.
        req.user = jwt.verify(token, config.jwtSecret);
        req.user.isRole = (role) => !!req.user.roles.find((r) => r.role === role);
      }
    } catch {
      req.user = null;
    }
  }
  next();
}

/**
 * Method to authenticate the token. If the user is not null, then we call the `next` parameter function. Otherwise send a 401 Unauthorized message.
 * @param {*} req request
 * @param {*} res response
 * @param {*} next function to call next
 */
authRouter.authenticateToken = (req, res, next) => {
  if (!req.user) {
    return res.status(401).send({ message: 'unauthorized' });
  }
  next();
};

/**
 * Method to register a user. Gets the name, email, and password from the json body, and sends a 400 response if any of them are missing. If there, then the
 *   information will be put into the database and logged in with setAuth().
 * @returns json of user and authToken
 */
authRouter.post(
  '/',
  asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'name, email, and password are required' });
    }
    const user = await DB.addUser({ name, email, password, roles: [{ role: Role.Diner }] });
    const auth = await setAuth(user);
    res.json({ user: user, token: auth });
  })
);

/**
 * Method to login a user. Gets the email and password from the json body, and then gets the user from the database. Then it will pass that user into 
 *   seAuth to be logged in.
 * @returns json of user and authToken
 */
authRouter.put(
  '/',
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    const user = await DB.getUser(email, password);
    const auth = await setAuth(user);
    res.json({ user: user, token: auth });
  })
);

/**
 * Method to logout a user. Calls clearAuth, passing in the request.
 * @Returns json of "logout successful"
 */
authRouter.delete(
  '/',
  authRouter.authenticateToken,
  asyncHandler(async (req, res) => {
    await clearAuth(req);
    res.json({ message: 'logout successful' });
  })
);

/**
 * Gives the user an authToken, and then logs the user in
 * @param {*} user 
 * @returns authToken
 */
async function setAuth(user) {
  const token = jwt.sign(user, config.jwtSecret);
  await DB.loginUser(user.id, token);
  return token;
}

/**
 * Gets the authToken from the request, and if there is a token, deletes it from the database.
 * @param {*} req request
 */
async function clearAuth(req) {
  const token = readAuthToken(req);
  if (token) {
    await DB.logoutUser(token);
  }
}

/**
 * Gets the authHeader from the request, and splits it up by spaces and returns the second instance of the split array.
 * @param {*} req request
 * @returns authToken string or null
 */
function readAuthToken(req) {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    return authHeader.split(' ')[1];
  }
  return null;
}

module.exports = { authRouter, setAuthUser, setAuth };
