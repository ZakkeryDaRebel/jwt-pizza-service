const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const config = require('../config.js');
const { StatusCodeError } = require('../endpointHelper.js');
const { Role } = require('../model/model.js');
const dbModel = require('./dbModel.js');
const logger = require('../logger.js');

class DB {
  constructor() {
    this.initialized = this.initializeDatabase();
  }

  async getMenu() {
    const connection = await this.getConnection();
    try {
      const rows = await this.query(connection, `SELECT * FROM menu`);
      return rows;
    } finally {
      connection.end();
    }
  }

  async addMenuItem(item) {
    const connection = await this.getConnection();
    try {
      const addResult = await this.query(connection, `INSERT INTO menu (title, description, image, price) VALUES (?, ?, ?, ?)`, [item.title, item.description, item.image, item.price]);
      return { ...item, id: addResult.insertId };
    } finally {
      connection.end();
    }
  }

  async addUser(user) {
    const connection = await this.getConnection();
    try {
      const hashedPassword = await bcrypt.hash(user.password, 10);

      const userResult = await this.query(connection, `INSERT INTO user (name, email, password) VALUES (?, ?, ?)`, [user.name, user.email, hashedPassword]);
      const userId = userResult.insertId;
      for (const role of user.roles) {
        switch (role.role) {
          case Role.Franchisee: {
            const franchiseId = await this.getID(connection, 'name', role.object, 'franchise');
            await this.query(connection, `INSERT INTO userRole (userId, role, objectId) VALUES (?, ?, ?)`, [userId, role.role, franchiseId]);
            break;
          }
          default: {
            await this.query(connection, `INSERT INTO userRole (userId, role, objectId) VALUES (?, ?, ?)`, [userId, role.role, 0]);
            break;
          }
        }
      }
      return { ...user, id: userId, password: undefined };
    } finally {
      connection.end();
    }
  }

  async getUser(email, password) {
    const connection = await this.getConnection();
    try {
      const userResult = await this.query(connection, `SELECT * FROM user WHERE email=? ORDER BY id DESC`, [email]);
      if (!userResult.length || !password) {
        throw new StatusCodeError('unknown user', 404);
      }
      let matchedUser = null;
      let matchedRoles = [];
      for (const candidate of userResult) {
        if (!await bcrypt.compare(password, candidate.password)) {
          continue;
        }
        const roleResult = await this.query(connection, `SELECT * FROM userRole WHERE userId=?`, [candidate.id]);
        const roles = roleResult.map((r) => {
          return { objectId: r.objectId || undefined, role: r.role };
        });
        if (!matchedUser || roles.length > matchedRoles.length) {
          matchedUser = candidate;
          matchedRoles = roles;
        }
        if (roles.length > 0) {
          break;
        }
      }
      if (!matchedUser) {
        throw new StatusCodeError('unknown user', 404);
      }
      return { ...matchedUser, roles: matchedRoles, password: undefined };
    } finally {
      connection.end();
    }
  }

  /**
   * Get Users
   * @param {*} authUser 
   * @param {*} page 
   * @param {*} limit 
   * @param {*} nameFilter 
   * @returns 
   */
  async getUsers(authUser, page = 0, limit = 10, nameFilter = '*') {
    const connection = await this.getConnection();

    const safeLimit = this.parsePaginationValue(limit, 10, 1, 100);
    const safePage = this.parsePaginationValue(page, 0, 0, 10000);
    const offset = safePage * safeLimit;
    nameFilter = nameFilter.replace(/\*/g, '%');

    try {
      let users = await this.query(connection, `SELECT id, name, email FROM user WHERE name LIKE ? LIMIT ${safeLimit + 1} OFFSET ${offset}`, [nameFilter]);

      const more = users.length > safeLimit;
      if (more) {
        users = users.slice(0, safeLimit);
      }

      for (const user of users) {
        user.roles = await this.query(connection, `SELECT role FROM userRole WHERE userId=?`, [user.id]);
      }
      return [users, more];
    } finally {
      connection.end();
    }
  }

  async updateUser(userId, name, email, password) {
    const connection = await this.getConnection();
    try {
      const safeUserId = Number.parseInt(userId, 10);
      if (!Number.isInteger(safeUserId) || safeUserId <= 0) {
        throw new StatusCodeError('invalid user id', 400);
      }

      const updates = [];
      const values = [];
      if (password) {
        if (typeof password !== 'string') {
          throw new StatusCodeError('invalid password', 400);
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        updates.push('password=?');
        values.push(hashedPassword);
      }
      if (email) {
        if (typeof email !== 'string') {
          throw new StatusCodeError('invalid email', 400);
        }
        updates.push('email=?');
        values.push(email);
      }
      if (name) {
        if (typeof name !== 'string') {
          throw new StatusCodeError('invalid name', 400);
        }
        updates.push('name=?');
        values.push(name);
      }
      if (updates.length > 0) {
        values.push(safeUserId);
        const query = `UPDATE user SET ${updates.join(', ')} WHERE id=?`;
        await this.query(connection, query, values);
      }
      return this.getUser(email, password);
    } finally {
      connection.end();
    }
  }

  async deleteUser(userID) {
    const connection = await this.getConnection();
    try {
      await connection.beginTransaction();
      try {
        await this.query(connection, `DELETE FROM userRole WHERE userId=?`, [userID]);
        await this.query(connection, `DELETE FROM user WHERE id=?`, [userID]);
        await connection.commit();
      } catch {
        await connection.rollback();
        throw new StatusCodeError('unable to delete user', 500);
      }
    } finally {
      connection.end();
    }
  }

  async loginUser(userId, token) {
    token = this.getTokenSignature(token);
    const connection = await this.getConnection();
    try {
      await this.query(connection, `INSERT INTO auth (token, userId) VALUES (?, ?) ON DUPLICATE KEY UPDATE token=VALUES(token), userId=VALUES(userId)`, [token, userId]);
    } finally {
      connection.end();
    }
  }

  async isLoggedIn(token) {
    token = this.getTokenSignature(token);
    const connection = await this.getConnection();
    try {
      const authResult = await this.query(connection, `SELECT userId FROM auth WHERE token=?`, [token]);
      return authResult.length > 0;
    } finally {
      connection.end();
    }
  }

  async logoutUser(token) {
    token = this.getTokenSignature(token);
    const connection = await this.getConnection();
    try {
      await this.query(connection, `DELETE FROM auth WHERE token=?`, [token]);
    } finally {
      connection.end();
    }
  }

  async getOrders(user, page = 1) {
    const connection = await this.getConnection();
    try {
      const offset = this.getOffset(page, config.db.listPerPage);
      const orders = await this.query(connection, `SELECT id, franchiseId, storeId, date FROM dinerOrder WHERE dinerId=? LIMIT ${offset},${config.db.listPerPage}`, [user.id]);
      for (const order of orders) {
        let items = await this.query(connection, `SELECT id, menuId, description, price FROM orderItem WHERE orderId=?`, [order.id]);
        order.items = items;
      }
      return { dinerId: user.id, orders: orders, page };
    } finally {
      connection.end();
    }
  }

  async validateOrder(user, order) {
    const connection = await this.getConnection();
    try {
      // 1. Validate user exists and matches
      if (!user || !user.id || !user.email) {
        throw new StatusCodeError('Invalid user object', 400);
      }
      const userResult = await this.query(connection, `SELECT * FROM user WHERE id=?`, [user.id]);
      if (!userResult || userResult.length === 0) {
        throw new StatusCodeError('User does not exist', 404);
      }
      const dbUser = userResult[0];
      if (dbUser.email !== user.email) {
        throw new StatusCodeError('User mismatch', 403);
      }

      // 2. Validate franchiseId
      try {
        await this.getID(connection, 'id', order.franchiseId, 'franchise');
      } catch {
        throw new StatusCodeError('Invalid franchiseId', 400);
      }

      // 3. Validate storeId
      try {
        await this.getID(connection, 'id', order.storeId, 'store');
      } catch {
        throw new StatusCodeError('Invalid storeId', 400);
      }

      // 4. Validate order items
      if (!Array.isArray(order.items) || order.items.length === 0) {
        throw new StatusCodeError('Order must have at least one item', 400);
      }
      for (const item of order.items) {
        // Validate menuId exists
        let menuRows;
        try {
          menuRows = await this.query(connection, `SELECT id, title, price FROM menu WHERE id=?`, [item.menuId]);
        } catch {
          throw new StatusCodeError('Database error during menu validation', 500);
        }
        if (!menuRows || menuRows.length === 0) {
          throw new StatusCodeError(`Invalid menuId: ${item.menuId}`, 400);
        }
        const menu = menuRows[0];
        if (menu.title !== item.description || Number(menu.price) !== Number(item.price)) {
          throw new StatusCodeError(`Menu item data mismatch for menuId ${item.menuId}`, 400);
        }
      }
      // If all checks pass, return true
      return true;
    } finally {
      connection.end();
    }
  }

  async addDinerOrder(user, order) {
    const connection = await this.getConnection();
    try {
      const orderResult = await this.query(connection, `INSERT INTO dinerOrder (dinerId, franchiseId, storeId, date) VALUES (?, ?, ?, now())`, [user.id, order.franchiseId, order.storeId]);
      const orderId = orderResult.insertId;
      for (const item of order.items) {
        const menuId = await this.getID(connection, 'id', item.menuId, 'menu');
        await this.query(connection, `INSERT INTO orderItem (orderId, menuId, description, price) VALUES (?, ?, ?, ?)`, [orderId, menuId, item.description, item.price]);
      }
      return { ...order, id: orderId };
    } finally {
      connection.end();
    }
  }

  async createFranchise(franchise) {
    const connection = await this.getConnection();
    try {
      for (const admin of franchise.admins) {
        const adminUser = await this.query(connection, `SELECT id, name FROM user WHERE email=?`, [admin.email]);
        if (adminUser.length == 0) {
          throw new StatusCodeError(`unknown user for franchise admin ${admin.email} provided`, 404);
        }
        admin.id = adminUser[0].id;
        admin.name = adminUser[0].name;
      }

      const franchiseResult = await this.query(connection, `INSERT INTO franchise (name) VALUES (?)`, [franchise.name]);
      franchise.id = franchiseResult.insertId;

      for (const admin of franchise.admins) {
        await this.query(connection, `INSERT INTO userRole (userId, role, objectId) VALUES (?, ?, ?)`, [admin.id, Role.Franchisee, franchise.id]);
      }

      return franchise;
    } finally {
      connection.end();
    }
  }

  async deleteFranchise(franchiseId) {
    const connection = await this.getConnection();
    try {
      await connection.beginTransaction();
      try {
        await this.query(connection, `DELETE FROM store WHERE franchiseId=?`, [franchiseId]);
        await this.query(connection, `DELETE FROM userRole WHERE objectId=?`, [franchiseId]);
        await this.query(connection, `DELETE FROM franchise WHERE id=?`, [franchiseId]);
        await connection.commit();
      } catch {
        await connection.rollback();
        throw new StatusCodeError('unable to delete franchise', 500);
      }
    } finally {
      connection.end();
    }
  }

  /**
   * SQL LIKE operator searches for a specific pattern in a column. For example, if you put %the% as the nameFiler, it will
   *   get all the Franchises that have the word 'the' in it
   * @param {*} authUser 
   * @param {*} page 
   * @param {*} limit 
   * @param {*} nameFilter 
   * @returns 
   */
  async getFranchises(authUser, page = 0, limit = 10, nameFilter = '*') {
    const connection = await this.getConnection();

    const safeLimit = this.parsePaginationValue(limit, 10, 1, 100);
    const safePage = this.parsePaginationValue(page, 0, 0, 10000);
    const offset = safePage * safeLimit;
    nameFilter = nameFilter.replace(/\*/g, '%');

    try {
      let franchises = await this.query(connection, `SELECT id, name FROM franchise WHERE name LIKE ? LIMIT ${safeLimit + 1} OFFSET ${offset}`, [nameFilter]);

      const more = franchises.length > safeLimit;
      if (more) {
        franchises = franchises.slice(0, safeLimit);
      }

      for (const franchise of franchises) {
        if (authUser?.isRole(Role.Admin)) {
          await this.getFranchise(franchise);
        } else {
          franchise.stores = await this.query(connection, `SELECT id, name FROM store WHERE franchiseId=?`, [franchise.id]);
        }
      }
      return [franchises, more];
    } finally {
      connection.end();
    }
  }

  async getUserFranchises(userId) {
    const connection = await this.getConnection();
    try {
      let franchiseIds = await this.query(connection, `SELECT objectId FROM userRole WHERE role='franchisee' AND userId=?`, [userId]);
      if (franchiseIds.length === 0) {
        return [];
      }

      franchiseIds = franchiseIds.map((v) => v.objectId);
      const franchises = await this.query(connection, `SELECT id, name FROM franchise WHERE id in (${franchiseIds.join(',')})`);
      for (const franchise of franchises) {
        await this.getFranchise(franchise);
      }
      return franchises;
    } finally {
      connection.end();
    }
  }

  async getFranchise(franchise) {
    const connection = await this.getConnection();
    try {
      franchise.admins = await this.query(connection, `SELECT u.id, u.name, u.email FROM userRole AS ur JOIN user AS u ON u.id=ur.userId WHERE ur.objectId=? AND ur.role='franchisee'`, [franchise.id]);

      franchise.stores = await this.query(connection, `SELECT s.id, s.name, COALESCE(SUM(oi.price), 0) AS totalRevenue FROM dinerOrder AS do JOIN orderItem AS oi ON do.id=oi.orderId RIGHT JOIN store AS s ON s.id=do.storeId WHERE s.franchiseId=? GROUP BY s.id`, [franchise.id]);

      return franchise;
    } finally {
      connection.end();
    }
  }

  async createStore(franchiseId, store) {
    const connection = await this.getConnection();
    try {
      const insertResult = await this.query(connection, `INSERT INTO store (franchiseId, name) VALUES (?, ?)`, [franchiseId, store.name]);
      return { id: insertResult.insertId, franchiseId, name: store.name };
    } finally {
      connection.end();
    }
  }

  async deleteStore(franchiseId, storeId) {
    const connection = await this.getConnection();
    try {
      await this.query(connection, `DELETE FROM store WHERE franchiseId=? AND id=?`, [franchiseId, storeId]);
    } finally {
      connection.end();
    }
  }

  getOffset(currentPage = 1, listPerPage) {
    return (currentPage - 1) * [listPerPage];
  }

  parsePaginationValue(value, defaultValue, min, max) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isInteger(parsed)) {
      return defaultValue;
    }
    return Math.min(Math.max(parsed, min), max);
  }

  getTokenSignature(token) {
    const parts = token.split('.');
    if (parts.length > 2) {
      return parts[2];
    }
    return '';
  }

  async query(connection, sql, params) {
    const [results] = await logger.logQuery(sql, params, async () => {
      return await connection.execute(sql, params);
    })
    return results;
  }

  async getID(connection, key, value, table) {
    const [rows] = await connection.execute(`SELECT id FROM ${table} WHERE ${key}=?`, [value]);
    if (rows.length > 0) {
      return rows[0].id;
    }
    throw new Error('No ID found');
  }

  async getConnection() {
    // Make sure the database is initialized before trying to get a connection.
    await this.initialized;
    return this._getConnection();
  }

  async _getConnection(setUse = true) {
    const connection = await mysql.createConnection({
      host: config.db.connection.host,
      user: config.db.connection.user,
      password: config.db.connection.password,
      connectTimeout: config.db.connection.connectTimeout,
      decimalNumbers: true,
    });
    if (setUse) {
      await connection.query(`USE ${config.db.connection.database}`);
    }
    return connection;
  }

  async initializeDatabase() {
    try {
      const connection = await this._getConnection(false);
      try {
        const dbExists = await this.checkDatabaseExists(connection);
        console.log(dbExists ? 'Database exists' : 'Database does not exist, creating it');

        await connection.query(`CREATE DATABASE IF NOT EXISTS ${config.db.connection.database}`);
        await connection.query(`USE ${config.db.connection.database}`);

        if (!dbExists) {
          console.log('Successfully created database');
        }

        for (const statement of dbModel.tableCreateStatements) {
          await connection.query(statement);
        }

        const [rows] = await connection.execute(
          `SELECT * FROM userRole WHERE role=?`,
          [Role.Admin]
        );

        if (rows.length === 0) {
          const bootstrapName = process.env.BOOTSTRAP_ADMIN_NAME;
          const bootstrapEmail = process.env.BOOTSTRAP_ADMIN_EMAIL;
          const bootstrapPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD;
          const isProd = process.env.NODE_ENV === 'production';
          const useDefaults = !isProd && !bootstrapName && !bootstrapEmail && !bootstrapPassword;

          if (!useDefaults && (!bootstrapName || !bootstrapEmail || !bootstrapPassword)) {
            throw new Error('Missing bootstrap admin credentials');
          }

          const adminName = useDefaults ? '常用名字' : bootstrapName;
          const adminEmail = useDefaults ? 'a@jwt.com' : bootstrapEmail;
          const adminPassword = useDefaults ? 'admin' : bootstrapPassword;
          const hashedPassword = await bcrypt.hash(adminPassword, 10);

          const [result] = await connection.execute(
            `INSERT INTO user (name, email, password) VALUES (?, ?, ?)`,
            [adminName, adminEmail, hashedPassword]
          );

          await connection.execute(
            `INSERT INTO userRole (userId, role, objectId) VALUES (?, ?, ?)`,
            [result.insertId, Role.Admin, 0]
          );
        }
      } finally {
        connection.end();
      }
    } catch (err) {
      console.error(JSON.stringify({ message: 'Error initializing database', exception: err.message, connection: config.db.connection }));
    }
  }

  async checkDatabaseExists(connection) {
    const [rows] = await connection.execute(`SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = ?`, [config.db.connection.database]);
    return rows.length > 0;
  }
}

const db = new DB();
module.exports = { Role, DB: db };
