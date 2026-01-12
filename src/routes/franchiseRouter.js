const express = require('express');
const { DB, Role } = require('../database/database.js');
const { authRouter } = require('./authRouter.js');
const { StatusCodeError, asyncHandler } = require('../endpointHelper.js');

const franchiseRouter = express.Router();

franchiseRouter.docs = [
  {
    method: 'GET',
    path: '/api/franchise?page=0&limit=10&name=*',
    description: 'List all the franchises',
    example: `curl localhost:3000/api/franchise&page=0&limit=10&name=pizzaPocket`,
    response: { franchises: [{ id: 1, name: 'pizzaPocket', admins: [{ id: 4, name: 'pizza franchisee', email: 'f@jwt.com' }], stores: [{ id: 1, name: 'SLC', totalRevenue: 0 }] }], more: true },
  },
  {
    method: 'GET',
    path: '/api/franchise/:userId',
    requiresAuth: true,
    description: `List a user's franchises`,
    example: `curl localhost:3000/api/franchise/4  -H 'Authorization: Bearer tttttt'`,
    response: [{ id: 2, name: 'pizzaPocket', admins: [{ id: 4, name: 'pizza franchisee', email: 'f@jwt.com' }], stores: [{ id: 4, name: 'SLC', totalRevenue: 0 }] }],
  },
  {
    method: 'POST',
    path: '/api/franchise',
    requiresAuth: true,
    description: 'Create a new franchise',
    example: `curl -X POST localhost:3000/api/franchise -H 'Content-Type: application/json' -H 'Authorization: Bearer tttttt' -d '{"name": "pizzaPocket", "admins": [{"email": "f@jwt.com"}]}'`,
    response: { name: 'pizzaPocket', admins: [{ email: 'f@jwt.com', id: 4, name: 'pizza franchisee' }], id: 1 },
  },
  {
    method: 'DELETE',
    path: '/api/franchise/:franchiseId',
    requiresAuth: true,
    description: `Delete a franchises`,
    example: `curl -X DELETE localhost:3000/api/franchise/1 -H 'Authorization: Bearer tttttt'`,
    response: { message: 'franchise deleted' },
  },
  {
    method: 'POST',
    path: '/api/franchise/:franchiseId/store',
    requiresAuth: true,
    description: 'Create a new franchise store',
    example: `curl -X POST localhost:3000/api/franchise/1/store -H 'Content-Type: application/json' -d '{"franchiseId": 1, "name":"SLC"}' -H 'Authorization: Bearer tttttt'`,
    response: { id: 1, name: 'SLC', totalRevenue: 0 },
  },
  {
    method: 'DELETE',
    path: '/api/franchise/:franchiseId/store/:storeId',
    requiresAuth: true,
    description: `Delete a store`,
    example: `curl -X DELETE localhost:3000/api/franchise/1/store/1  -H 'Authorization: Bearer tttttt'`,
    response: { message: 'store deleted' },
  },
];

/**
 * Method to get Franchises. Calls the database to getFranchises, passing in the request, and gets the franchises and if there are more franchises left.
 * @returns json of the list of franchises and boolean of it there are more franchises
 */
franchiseRouter.get(
  '/',
  asyncHandler(async (req, res) => {
    const [franchises, more] = await DB.getFranchises(req.user, req.query.page, req.query.limit, req.query.name);
    res.json({ franchises, more });
  })
);

/**
 * Method to get User Franchises. Gets the userID from the request, and checks to see if that is a valid Number, and also if the user is an Admin. Then if the
 *   user is an Admin, it will get the franchises associated with the User.
 * @returns an empty array or an array of franchises the user has.
 */
franchiseRouter.get(
  '/:userId',
  authRouter.authenticateToken,
  asyncHandler(async (req, res) => {
    let result = [];
    const userId = Number(req.params.userId);
    if (req.user.id === userId || req.user.isRole(Role.Admin)) {
      result = await DB.getUserFranchises(userId);
    }

    res.json(result);
  })
);

/**
 * Method to create a Franchise. If the user is not an admin, throws a 403 error, stating that they can't create a franchise. Otherwise, it will 
 *   return the response from going into the database and creating a new Franchise. 
 */
franchiseRouter.post(
  '/',
  authRouter.authenticateToken,
  asyncHandler(async (req, res) => {
    if (!req.user.isRole(Role.Admin)) {
      throw new StatusCodeError('unable to create a franchise', 403);
    }

    const franchise = req.body;
    res.send(await DB.createFranchise(franchise));
  })
);

/**
 * Method to delete a franchise. Checks to see if the franchiseID from the request is a valid number, then calls the database to delete said franchise. 
 * @returns Json of "franchise deleted"
 */
franchiseRouter.delete(
  '/:franchiseId',
  asyncHandler(async (req, res) => {
    const franchiseId = Number(req.params.franchiseId);
    await DB.deleteFranchise(franchiseId);
    res.json({ message: 'franchise deleted' });
  })
);

/**
 * Method to create a store. First checks to see if the franchiseID is a valid Number, and then gets that franchise from the database. Then if the franchise is
 *   null, or if the user is not an Admin and not an admin of that franchise, then it will return a 403 error saying they are unable to create a store. 
 *   Otherwise it will return the json version of the response of entering the database and creating a store. 
 */
franchiseRouter.post(
  '/:franchiseId/store',
  authRouter.authenticateToken,
  asyncHandler(async (req, res) => {
    const franchiseId = Number(req.params.franchiseId);
    const franchise = await DB.getFranchise({ id: franchiseId });
    if (!franchise || (!req.user.isRole(Role.Admin) && !franchise.admins.some((admin) => admin.id === req.user.id))) {
      throw new StatusCodeError('unable to create a store', 403);
    }

    res.send(await DB.createStore(franchise.id, req.body));
  })
);

/**
 * Method to delete a store. Checks to make sure the franchiseID is a valid number, then gets the frnachise with that ID. Then if that franchise is null, or
 *   if the user is not an Admin, or is not an Admin of that Franchise, then it returns a 403 error stating that they are unable to delete a store. If not, then
 *   it checks to see if the storeID is a valid number, and passes that to the database to delete that store. It finally returns the json version of "store deleted"
 */
franchiseRouter.delete(
  '/:franchiseId/store/:storeId',
  authRouter.authenticateToken,
  asyncHandler(async (req, res) => {
    const franchiseId = Number(req.params.franchiseId);
    const franchise = await DB.getFranchise({ id: franchiseId });
    if (!franchise || (!req.user.isRole(Role.Admin) && !franchise.admins.some((admin) => admin.id === req.user.id))) {
      throw new StatusCodeError('unable to delete a store', 403);
    }

    const storeId = Number(req.params.storeId);
    await DB.deleteStore(franchiseId, storeId);
    res.json({ message: 'store deleted' });
  })
);

module.exports = franchiseRouter;
