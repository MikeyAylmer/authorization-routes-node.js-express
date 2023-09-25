const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");
const ExpressError = require("../expressError");

// Authentication for JWT token signature decorating request with user property.
function authenticateJWT(req, res, next) {
  try {
    const payload = jwt.verify(req.body._token, SECRET_KEY); // return paylod(data) from token.
    req.user = payload;
    return next();
  } catch (e) {
    // we dont return next of error because jwt responds its own error
    return next();// we just want to return the error handler message not jwt message.
  }
}

// if no req.user then thorw error unauthorized.
function ensureLoggedIn(req, res, next) {
  if (!req.user) {
    const e = new ExpressError("Unauthorized", 401);
    return next(e);// we return e because its set to the value of new express error.
  } else {
    return next();
  }
}

// function to check is user is admin or not and if they are not admin cant enter.
function ensureAdmin(req, res, next) {
  if (!req.user || req.user.type !== 'admin') {
    return next(new ExpressError("Must be an admin to go here!", 401))
  }
  return next();
}

// export the middleware functions.
module.exports = { authenticateJWT, ensureLoggedIn, ensureAdmin };