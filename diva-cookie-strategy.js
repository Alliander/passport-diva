/**
 * Module dependencies.
 */
var passport = require("passport-strategy");
var diva = require("diva-irma-js");
var util = require("util");

/**
 * Creates an instance of `DivaCookieStrategy`.
 *
 * Options:
 *
 *   - `cookieName`  Cookie name (defaults to "diva-session")
 *
 * Examples:
 *
 *  passport.use(new DivaCookieStrategy({ cookieName: 'my-cookie'}));
 *
 * @constructor
 * @param {Object} [options]
 * @param {Function} verify
 * @api public
 */
function DivaCookieStrategy(options) {
  options = options || {};
  passport.Strategy.call(this);
  this.name = "diva";
  this._cookieName = options.cookieName || "diva-session";
}

/**
 * Inherits from `passport.Strategy`
 */
util.inherits(DivaCookieStrategy, passport.Strategy);

/**
 * Authenticate request based on cookie.
 *
 * @param {Object} req
 * @api protected
 */
DivaCookieStrategy.prototype.authenticate = function(req) {
  // if (!req.cookies) {
  //   throw new TypeError("Maybe you forgot to use cookie-parser?");
  // }

  if (!req.signedCookies) {
    throw new TypeError("Maybe you forgot to use cookie-encrypter?");
  }

  // TODO move this to diva-irma-js except for the cookie part
  let sessionState;
  if (typeof req.signedCookies[this._cookieName] === 'undefined' ||
      typeof req.signedCookies[this._cookieName].user === 'undefined' ||
      typeof req.signedCookies[this._cookieName].user.sessionId === 'undefined' ||
      typeof req.signedCookies[this._cookieName].user.attributes === 'undefined') {
    sessionState = diva.deauthenticate();
  } else {
    sessionState = req.signedCookies[this._cookieName];
  }

  if (!sessionState) {
    return this.fail(401); //TODO this should be unreachable code
  } else {
    req.divaSessionState = sessionState;
    return this.success(sessionState.user);
  }
};

/**
 * Expose `DivaCookieStrategy`
 */
module.exports = DivaCookieStrategy;

const defaultSessionIdGenerator = () => Math.rand();
