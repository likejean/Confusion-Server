var express = require('express');
var router = express.Router();
const bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var User = require('../models/users');

router.use(bodyParser.json());
router.use(bodyParser.urlencoded({ extended: true }));
router.use(cookieParser());

/* GET users listing. */
router.get('/', (req, res, next) => {
  	res.send('respond with a resource');
});

router.post('/signup', (req, res, next) => {
	User.findOne({username: req.body.username})
	.then(user => {
		if (user != null) {
			var err = new Error('User ' + req.body.username + ' already exists');1
			err.status = 403;
			next(err);
		}
		else {
			return User.create({
				username: req.body.username,
				password: req.body.password
			})
		}
	})
	.then(user => {
		res.statusCode = 200;
		res.setHeader('Content-Type', 'application/json');
		res.json({status: 'Registration Successful', user: user})
	}, err => next(err))
	.catch(err => next(err));
});

router.post('/login', (req, res, next) => {
	
	if(!req.session.user) {
		var authHeader = req.headers.authorization;

		if (!authHeader) {
			var err = new Error('You are not authenthicated!');

			res.setHeader('WWW-Authenticate', 'Basic');
			err.status = 401;
			return next(err);
		}

		var auth = new Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');

		var username = auth[0];
		var password = auth[1];

		User.findOne({username: username})
		.then(user => {
			if (user === null) {
				var err = new Error('User ' + username + ' does not exists');
				err.status = 403;
				return next(err);
			}
			else if (user.password !== password){
				var err = new Error('Your password is invalid!');
				err.status = 403;
				return next(err);
			}
			else if (user.username === username && user.password === password) {
				req.session.user = 'authenticated';
				res.statusCode = 200;
				res.setHeader('Content-Type', 'text/plain');
				res.end('You are athenticated!');
			}
		})
		.catch(err => next(err));		
	}
	else {
		res.statusCode = 200;
		res.setHeader('Content-Type', 'text/plain');
		res.end('You are ALREADY athenticated!')
	}
});

router.get('/logout', (req, res) => {
	if (req.session) {
		req.session.destroy();
		res.clearCookie('session-id');
		res.redirect('/');
	}
	else {
		var err = new Error('You are not logged in!');
		err.status = 403;
		next(err);
	}
});

module.exports = router;
