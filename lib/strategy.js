/**
 * Module dependencies.
 */
var passport = require('passport-strategy'),
    util = require('util'),
    moment = require('moment'),
    querystring= require('querystring'),
    debug = require('debug')('passport:oauth2');

/**
 * Creates an instance of `OAuth2RefreshTokenStrategy`.
 *
 * @constructor
 * @param {Object} options
 * @api public
 */
function OAuth2RefreshTokenStrategy(options) {
  this._options = {
    refreshWindow: options.refreshWindow || 10,
    userProperty: options.userProperty || 'ticket',
    authenticationURL: options.authenticationURL,
    callbackParameter: options.callbackParameter
  };
  this.name = 'oauth2refresh';

  passport.Strategy.call(this);
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(OAuth2RefreshTokenStrategy, passport.Strategy);

/**
 * Authenticate request by using stored access token. If the access token has expired,
 * provider will try obtain a new token using store refresh token.
 *
 * @param {Object} req
 * @api protected
 */
OAuth2RefreshTokenStrategy.prototype.authenticate = function(req, options) {
  var self = this;

  if (!this._oauth2Strategy) {
    return this.error(new Error('OAuth2Strategy was not registered with UseOAuth2Strategy method'));
  }

  if (req.query && req.query.code) {
    return this._oauth2Strategy.authenticate(req, options);
  }

  var authenticationURL = this._options.authenticationURL;

  if (authenticationURL && this._options.callbackParameter) {
    authenticationURL += '?' +
      encodeURIComponent(this._options.callbackParameter) + '=' +
      encodeURIComponent(req.url);
  }

  if (!req.isAuthenticated() || !req.user[this._options.userProperty]) {
    debug('User is not authenticated.');

    if (!authenticationURL || options.noredirect) {
      return this.fail();
    }

    return this.redirect(authenticationURL);
  }

  var ticket = req.user[this._options.userProperty],
      expires = ticket.expires ?
        moment.unix(ticket.expires - (this._options.refreshWindow || 0)) :
        0;

  if (!expires || expires.isAfter(moment())) {
    return this.success(req.user, ticket);
  }

  debug('New access token required.');
  debug('Old access token: ' + ticket.access_token);
  debug('Old refresh token: ' + ticket.refresh_token);
  debug('Expires: ' + expires ? expires.toString() : 'never');

  var params = {
    grant_type: 'refresh_token'
  };
  this._oauth2Strategy._oauth2.getOAuthAccessToken(
    ticket.refresh_token,
    params,
    function(err, accessToken, refreshToken, params) {
      if (err) {
        debug('Error refreshing the access token: ' + err);

        return self.fail(err);
      }

      if (accessToken && refreshToken) {
        var expires = params.expires_in ?
          moment().add(params.expires_in, 'seconds') :
          null;

        ticket.access_token = accessToken;
        ticket.refresh_token = refreshToken;

        if (expires) {
          ticket.expires = expires.unix();
        }

        debug('Access token refreshed successfully.');
        debug('New access token: ' + ticket.access_token);
        debug('New refresh token: ' + ticket.refresh_token);
        debug('Expires: ' + expires ? expires.toString() : 'never');

        return self.success(req.user, ticket);
      }

      if (params.error) {
        debug('Invalid or revoked refresh token: ' + JSON.stringify(params));

        req.logout();

        if (!authenticationURL || options.noredirect) {
          return self.fail(params.error_description || 'Invalid or revoked refresh token.');
        }

        return self.redirect(authenticationURL);
      }

      debug('Error refreshing the access token: ' + JSON.stringify(params));

      return self.fail('Error refreshing the access token');
    }
  );
};

/**
 * Add an existing OAuth2Strategy to use.
 *
 * @param {OAuth2Strategy} strategy
 * @api public
 */
OAuth2RefreshTokenStrategy.prototype.useOAuth2Strategy = function(strategy) {
  this._oauth2Strategy = strategy;
};

/**
 * Add an existing LocalStrategy to use.
 *
 * @param {LocalStrategy} strategy
 * @api public
 */
OAuth2RefreshTokenStrategy.prototype.useLocalStrategy = function(strategy) {
  this._localStrategy = strategy;
};

/**
 * Create a callback for OAuth2Strategy to store a recieved access token.
 *
 * @api public
 */
OAuth2RefreshTokenStrategy.prototype.getOAuth2StrategyCallback = function() {
  var self = this;
  return function(accessToken, refreshToken, params, profile, done) {
    if (!self._oauth2Strategy) {
      return done(new Error('OAuth2Strategy was not registered with UseOAuth2Strategy method'));
    }

    if (self._oauth2Strategy._passReqToCallback) {
      throw new Error('OAuth2Strategy.passReqToCallback must be set to false.');
    }

    if (params.error) {
      return done(null, false, { message: params.error });
    }

    profile = profile || {};

    var ticket = profile[self._options.userProperty] = {
      access_token: accessToken,
      refresh_token: refreshToken
    };

    if (params.expires_in) {
      ticket.expires = moment().add(params.expires_in, 'seconds').unix();
    }

    debug('New access token received.');
    debug('Access token: ' + ticket.access_token);
    debug('Refresh token: ' + ticket.refresh_token);
    debug('Expires: ' + (params.expires_in ? 'in ' + params.expires_in + ' seconds' : 'never'));

    if (done) {
      done(null, profile);
    }

    return profile;
  };
};

/**
* Create a callback for LocalStrategy to obtain a new access token using
* a 'password' OAuth2 grant request.
*
* @api public
*/
OAuth2RefreshTokenStrategy.prototype.getLocalStrategyCallback = function() {
  var self = this;
  return function(req, username, password, done) {
    if (!self._localStrategy) {
      return done(new Error('LocalStrategy was not registered with UseLocalStrategy method'));
    }

    if (!self._oauth2Strategy) {
      return done(new Error('OAuth2Strategy was not registered with UseOAuth2Strategy method'));
    }

    if (!self._localStrategy._passReqToCallback) {
      done = password;
      password = username;
      username = req;
      req = null;
    }

    var oauth2 = self._oauth2Strategy._oauth2;

    var params = {
      grant_type: 'password',
      username: username,
      password: password,
      client_id: oauth2._clientId
    };

    oauth2._request(
      'POST',
      oauth2._getAccessTokenUrl(),
      { 'Content-Type': 'application/x-www-form-urlencoded' },
      querystring.stringify(params),
      null,
      function(err, data, response) {
        if (err) {
          debug('Unable to obtain an access token: ' + err.data);
          return done(err);
        }

        if (response.statusCode !== 200) {
          debug('Login request failed: ' + data);
          return done(null, false, { message: 'Login request has failed.' });
        }

        var payload;

        try
        {
          payload = JSON.parse(data);
        }
        catch(e)
        {
          debug('Error processing the response: ' + e + data);
          return done(null, false, { message: 'Unable to login.' });
        }

        if (payload.error) {
          var error = payload.error_description || 'Unable to login.';

          switch (payload.error) {
            case 'invalid_grant':
              error = 'Invalid username or password.';
              break;
          }

          debug('Error obtaining an access token: ' + data);
          return done(null, false, { message: error });
        }

        self._oauth2Strategy._loadUserProfile(payload.access_token, function(err, profile) {
          if (err) {
            debug('Error loading user profile: ' + err);
            return done(err);
          }

          profile = profile || {};

          var ticket = profile[self._options.userProperty] = {
            access_token: payload.access_token,
            refresh_token: payload.refresh_token
          };
          
          if (payload.expires_in) {
            ticket.expires = moment().add(payload.expires_in, 'seconds').unix();
          }

          debug('New access token received.');
          debug('Access token: ' + ticket.access_token);
          debug('Refresh token: ' + ticket.refresh_token);
          debug('Expires: ' + (payload.expires_in ? ('in ' + payload.expires_in + ' seconds') : 'never'));

          done(null, profile);
        });
      }
    );
  };
};

/**
 * Expose `OAuth2RefreshTokenStrategy`.
 */
module.exports = OAuth2RefreshTokenStrategy;
