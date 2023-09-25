/** Routes for demonstrating authentication in Express. */

const express = require("express");//import express app
const router = new express.Router();//middleware router
const ExpressError = require("../expressError");//import express error class's
const db = require("../db");//import database
const bcrypt = require("bcrypt");//import bcrypt
const jwt = require("jsonwebtoken");//import json web token
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");// import for hashed password rounds & secret key variable.
const { ensureLoggedIn, ensureAdmin } = require("../middleware/auth");

router.get('/', (req, res, next) => {
  res.send("APP IS WORKING!!!")
})

// POST/ route to save a username and password to database. 
router.post('/register', async (req, res, next) => {
  try {
    const { username, password } = req.body;//extract username, password from request body.
    // check for username or password.
    if (!username || !password) {
      throw new ExpressError("Username and password required", 400);
    }
    // hash password
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    // save to db
    const results = await db.query(`
      INSERT INTO users (username, password)
      VALUES ($1, $2)
      RETURNING username`,
      [username, hashedPassword]);// MAKE SURE TO USE HASHED PASSWORd
    return res.json(results.rows[0]);
  } catch (e) {
    // Check to see if error code equals error code.
    if (e.code === '23505') {
      return next(new ExpressError("Username taken. Please pick another!", 400));
    }
    return next(e)
  }
});

// Route to log a user in.
router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;//extract username, password from req.body
    // if no username, password given throw error.
    if (!username || !password) {
      throw new ExpressError("Username and password required", 400);
    }
    // find user from database.
    const results = await db.query(
      `SELECT username, password 
       FROM users
       WHERE username = $1`,
      [username]);
    const user = results.rows[0];
    // if user found do this.
    if (user) {
      // compare password with hashedPassword 
      if (await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username }, SECRET_KEY);//generates jwt token
        return res.json({ message: `Logged in!`, token })
      }
    }
    // if user not found throw error msg and code.
    throw new ExpressError("Invalid username/password", 400);
  } catch (e) {
    return next(e);
  }
})

// GET/ route for only people with verified access jwt tokens
router.get('/topsecret',
  ensureLoggedIn,// checks to see if the was a user request in the user property which means user token has been verified.
  (req, res, next) => {
    try {
      return res.json({ msg: "SIGNED IN! THIS IS TOP SECRET.  I LIKE PURPLE." })

    } catch (e) {
      return next(new ExpressError("Please login first!", 401))
    }
  })

router.get('/private', ensureLoggedIn, (req, res, next) => {
  return res.json({ msg: `Welcome to my VIP section, ${req.user.username}` })
})

router.get('/adminhome', ensureAdmin, (req, res, next) => {
  return res.json({ msg: `ADMIN DASHBOARD! WELCOME ${req.user.username}` })
})


module.exports = router;

