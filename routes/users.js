var express = require('express');
var router = express.Router();
const bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');


router.use(bodyParser.json());
router.use(bodyParser.urlencoded({ extended: true }));
router.use(cookieParser());

/* GET users listing. */
router.all('/',(req, res) => {	

	let pars = (Object.keys(req.body).length > 0)?req.body:req.query;
    res.send(pars);
})
.get('/', (req, res, next) => {	
	console.log('Cookies: ', req.cookies)
 
	// Cookies that have been signed
	console.log('Signed Cookies: ', req.signedCookies)
  	res.send('respond with a resource');
})
.post('/', (req, res, next) => {	  
	res.send(
	  req.query.id + ' ' 
	+ req.query.token + ' ' 
	+ req.query.geo);
});

module.exports = router;
