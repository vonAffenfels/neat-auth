let strategy = require("passport-facebook").Strategy;
let Tools = require("neat-base").Tools;
let Application = require("neat-base").Application;
let Promise = require("bluebird");
let crypto = require("crypto");

module.exports = function (passport, config, webserver) {
    passport.use(new strategy({
            clientID: config.facebookId,
            clientSecret: config.facebookSecret,
            callbackURL: config.facebookReturn,
            profileFields: ['id', 'displayName', 'email'],
            enableProof: true
                },
        function (req, token, tokenSecret, profile, done) {
            let userModel = Application.modules[Application.modules.auth.config.dbModuleName].getModel("user");

            if (req.user) {
                req.user.set("oauth.facebook", profile.id);
                return req.user.save({
                    validateBeforeSave: false
                }).then(() => {
                    return done(null, req.user);
                }, (err) => {
                    done(err);
                });
            }

            userModel.findOne({
                $or: [
                    {
                        openId: profile.id
                    },
                    {
                        "oauth.facebook": profile.id
                    }
                ]
            }).then((user) => {

                if (user) {
                    return done(null, user);
                }
                
                let emailProm = Promise.resolve(null);
                if (profile.emails.length) {
                    let email = profile.emails[0].value;
                    emailProm = userModel.findOne({
                        email: email
                    })
                }

                emailProm.then((user) => {
                    if (user) {
                        user.set("oauth.facebook", profile.id);
                        return user.save({
                            validateBeforeSave: false
                        }).then(() => {
                            return done(null, user);
                        }, (err) => {
                            done(err);
                        });
                    }

                    userModel.findOne({
                        username: profile.displayName
                    }).then((user) => {
                        if (user) {
                            user = new userModel({
                                username: profile.displayName + "-" + String(profile.id).substr(0, 3),
                                password: crypto.randomBytes(20).toString('hex'),
                                email: profile.emails.length ? profile.emails[0].value : null,
                                "activation.active": true,
                                "oauth.facebook": profile.id
                            });

                        } else {
                            user = new userModel({
                                username: profile.displayName,
                                password: crypto.randomBytes(20).toString('hex'),
                                email: profile.emails.length ? profile.emails[0].value : null,
                                "activation.active": true,
                                "oauth.facebook": profile.id
                            });
                        }

                        user.save({
                            validateBeforeSave: false
                        }, (err) => {
                            if (err) {
                                return done(err);
                            }

                            return done(null, user);
                        });
                    });
                })
            });
        }
    ));

    webserver.addRoute("get", "/auth/facebook", function (req, res, next) {
        req.session.returnTo = req.query.returnTo || "/";
        req.session.returnJSON = req.headers['user-agent'] === "APP-OAUTH";
        passport.authenticate('facebook', { scope: ['email'] })(req, res, next);
    });

    webserver.addRoute("get", "/auth/facebook/return", function (req, res, next) {
        passport.authenticate('facebook')(req, res, (err) => {
            if (req.session.returnJSON || req.query.json) {
                delete req.session.returnJSON;

                if (err) {
                    res.status(400);
                    return res.json({
                        message: err.message
                    });
                }

                return res.json(req.user);
            }

            if (err) {
                return res.redirect("/");
            } else {
                let returnTo = req.session.returnTo;
                delete req.session.returnTo;
                return res.redirect(returnTo);
            }
        });
    });

}