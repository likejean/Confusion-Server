var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy; //strategy for authenticating with a username and password.
var User = require('./models/users');
var JwtStrategy = require('passport-jwt').Strategy //strategy for authenticating with a JSON Web Token
var ExtractJwt = require('passport-jwt').ExtractJwt;
var jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens

/// passport-jwt => A Passport strategy for authenticating with a JSON Web Token
/// Passport is authentication middleware for Node, which serves one purpose, to authenticate requests


var config = require('./config.js');

///The Local strategy extracts the username and password from req.body 
///and verifies the user by verifying it against the User table.
exports.local = passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

exports.getToken = function(user) {
    return jwt.sign(user, config.secretKey,
        {expiresIn: 3600});
};

var opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.secretKey;

///configuration which reads the JWT from the http Authorization header with the scheme 'bearer'
exports.jwtPassport = passport.use(new JwtStrategy(opts,
    (jwt_payload, done) => {
        console.log("JWT payload: ", jwt_payload);
        User.findOne({_id: jwt_payload._id}, (err, user) => {
            if (err) {
                return done(err, false);
            }
            else if (user) {
                return done(null, user);
            }
            else {
                return done(null, false);
            }
        });
    }));


exports.verifyAdmin = function (req, res, next) {
        
        if (req.user.admin === true) { 
            next();
        } else {
            var err = new Error('THIS OPERATION FOR ADMINS ONLY! You are not authorized to perform this operation!');
            err.status = 403;
            return next(err);
        }
    };

exports.verifyUser = passport.authenticate('jwt', {session: false});