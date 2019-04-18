const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const authenticate = require('../authenticate');
const cors = require('./cors');
var Favorites = require('../models/favorites');

const favoriteRouter = express.Router();
favoriteRouter.use(bodyParser.json());

//// Route: /favorites/

favoriteRouter.route('/')
.options(cors.corsWithOptions, (req, res) => {
    res.sendStatus(200);
})
.get(cors.cors, authenticate.verifyUser, (req, res, next) => {
    console.log('REQ USER', req.user._id)
    Favorites.findOne({ user: req.user._id })
    .populate('user')
    .populate('dishes')
    .then((favorites) => {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.json(favorites);
    }, (err) => next(err))
    .catch((err) => next(err));
})
.post(cors.corsWithOptions, authenticate.verifyUser, (req, res, next) => {
    console.log("REQ.USER", req.user._id);

    Favorites.findOne({ user: req.user._id }, (err, favorite) => {
        if (err) return next(err);
        console.log("NEXTTTT")
        if (!favorite) {
            Favorites.create({ user: req.user._id })
            .then((favorite) => {
                for (var i = 0; i < req.body.length; i++)
                    if (favorite.dishes.indexOf(req.body[i]._id) < 0)                    
                        favorite.dishes.push(req.body[i]);
                favorite.save()
                .then((favorite) => {
                    console.log('Favorite created!..')
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'application/json');
                    res.json(favorite);
                })        
                .catch((err) => {
                    return next(err);
                }); 
            })
            .catch((err) => {
                return next(err);
            })
        } 
        else {
            res.statusCode = 403;
            res.setHeader('Content-Type', 'text/plain');
            res.end('Dish ' + req.params.dishId + ' already ')
        }    
    });
})
.put(cors.corsWithOptions, authenticate.verifyUser, (req, res, next) => {
    res.statusCode = 403;
    res.setHeader('Content-Type', 'text/plain');
    res.end('PUT operation not supported on /dishes');
})
.delete(cors.corsWithOptions, authenticate.verifyUser, (req, res, next) => {
    Favorites.remove({})
    .then((resp) => {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.json(resp);
    }, (err) => next(err))
    .catch((err) => next(err));
});




//// Route: /favorites/:dishId


favoriteRouter.route('/:dishId')
.options(cors.corsWithOptions, (req, res) => {
    res.sendStatus(200);
})
.get(cors.cors, authenticate.verifyUser, (req, res, next) => {
    res.statusCode = 403;
    res.setHeader('Content-Type', 'text/plain');
    res.end('GET operation not supported on /favorites/' + req.params.dishId);
})

.post(cors.corsWithOptions, authenticate.verifyUser, (req, res, next) => {
    console.log(req.user._id);

    Favorites.findOne({ user: req.user._id }, (err, favorite) => {
        if (err) return next(err);

        if (!favorite) {
            Favorites.create({ user: req.user._id })
            .then((favorite) => {                     
                favorite.dishes.push({"_id": req.params.dish});
                favorite.save()
                .then((favorite) => {
                    console.log('Favorite created!..')
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'application/json');
                    res.json(favorite);
                })        
                .catch((err) => {
                    return next(err);
                }); 
            })
            .catch((err) => {
                return next(err);
            })
        } 
        else {

            if (favorite.dishes.indexOf(req.params.dishId) < 0) {
                favorite.dishes.push({"_id": req.params.dish});
                favorite.save()
                .then((favorite) => {
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'application/json');
                    res.json(favorite);
                })
                .catch((err) => {
                    return next(err);
                })
            }
            else {
                res.statusCode = 403;
                res.setHeader('Content-Type', 'text/plain');
                res.end('Dish ' + req.params.dishId + ' already created');
            }           
        }  
    });
})


.put(cors.corsWithOptions, authenticate.verifyUser, (req, res, next) => {
    res.statusCode = 403;
    res.setHeader('Content-Type', 'text/plain');
    res.end('PUT operation not supported on /dishes');
})


.delete(cors.corsWithOptions, authenticate.verifyUser, (req, res, next) => {
    Favorites.findOne({ user: req.user._id }, (err, favorite) => {
        if (err) return next(err);
        
        var index = favorite.dishes.indexOf(req.params.dishId);
        if ( index >=0 ) {
            favorite.dishes.splice(index,1);
            favorite.save()           
            .then((favorite) => {
                console.log('Favorite Dish Deleted!..', favorite.dishes[index])
                res.statusCode = 200;
                res.setHeader('Content-Type', 'application/json');
                res.json(favorite);
            })        
            .catch((err) => {
                return next(err);
            })     
        }
        else {
            res.statusCode = 403;
            res.setHeader('Content-Type', 'text/plain');
            res.end('Dish ' + req.params.dishId + ' already deleted')
        }  
    })
});

module.exports = favoriteRouter;