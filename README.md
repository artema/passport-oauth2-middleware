Passport.js OAuth2 Middleware
==========================

Passport.js strategy that supports automatic **OAuth2 refresh tokens** and **OAuth2 password workflow**.

    npm install passport-oauth2-middleware

Example
==========================

    var OAuth2Strategy = require('passport-oauth2'),
        LocalStrategy = require('passport-local').Strategy,
        OAuth2RefreshTokenStrategy = require('passport-oauth2-middleware').Strategy,
        passport = require('passport');

    module.exports = function(app) {
      var refreshStrategy = new OAuth2RefreshTokenStrategy({
        refreshWindow: 10, // Time in seconds to perform a token refresh before it expires
        userProperty: 'ticket', // Active user property name to store OAuth tokens
        authenticationURL: '/login', // URL to redirect unathorized users to
        callbackParameter: 'callback' //URL query parameter name to pass a return URL
      });

      passport.use('main', refreshStrategy);  //Main authorization strategy that authenticates
                                              //user with store OAuth access token
                                              //and performs a tokne refresh when needed

      var oauthStartegy = new OAuth2Strategy({
        authorizationURL: 'https://authserver/oauth2/auth',
        tokenURL: 'https://authserver/oauth2/token',
        clientID: 'clientID',
        clientSecret: 'clientSecret',
        callbackURL: '/oauth/callback',
        passReqToCallback: false //Must be omitted or set to false in order to work with OAuth2RefreshTokenStrategy
      },
        refreshStrategy.getOAuth2StrategyCallback() //Create a callback for OAuth2Strategy
      );

      passport.use('oauth', oauthStartegy); //Strategy to perform regular OAuth2 code grant workflow
      refreshStrategy.useOAuth2Strategy(oauthStartegy); //Register the OAuth strategy
                                                        //to perform OAuth2 refresh token workflow

      var localStrategy = new LocalStrategy({
        usernameField : 'username',
        passwordField : 'password'
      },
        refreshStrategy.getLocalStrategyCallback() //Create a callback for LocalStrategy
      );

      passport.use('local', localStrategy); //Strategy to perform a username/password login
      refreshStrategy.useLocalStrategy(localStrategy); //Register the LocalStrategy
                                                       //to perform an OAuth 'password' workflow

      //GET /login
      app.get('/login', function(req, res){
       var callback = req.query.callback || '/';

       if (req.isAuthenticated()) {
         return res.redirect(callback);
       }

       res.render('login_page');
      });

      //POST /login
      app.post('/login', function(req, res, next) {
       var callback = req.query.callback || '/profile';

       passport.authenticate('local', function(err, user, info) {
         if (err || !user) {
           res.render('login_page', {
             error: info ? info.message : 'Unable to login.',
             username: req.body.username
           });
           return next();
         }

         req.logIn(user, function(err) {
           if (err) {
             return next(err);
           }

           return res.redirect(callback);
         });
       })(req, res, next);
      });

      //GET /oauth
      app.get('/oauth', passport.authenticate('oauth'));

      //GET /oauth/callback
      app.get('/oauth/callback', passport.authenticate('oauth'), function(req, res) {
        res.redirect('/profile');
      });

      //GET /profile
      app.get('/profile',
      passport.authenticate('main'), function(req, res) {
       res.render('profile_page');
      });

      //GET /api/data
      app.get('/api/data',
      passport.authenticate('main', {
        noredirect: true //Don't redirect a user to the authentication page, just show an error
      }), function(req, res) {
        res.render('profile_page');
      });
    };
