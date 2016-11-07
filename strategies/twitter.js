var strategy = require("passport-twitter").Strategy;
var Tools = require("neat-base").Tools;
var Application = require("neat-base").Application;

module.exports = function (passport, config, webserver) {

    passport.use(new strategy({
            consumerKey: config.twitterKey,
            consumerSecret: config.twitterSecret,
            callbackURL: config.twitterReturn,
            successReturnToOrRedirect: true,
            passReqToCallback: true
        },
        function (req, token, tokenSecret, profile, done) {
            var userModel = Application.modules[Application.modules.auth.config.dbModuleName].getModel("user");

            if (req.user) {
                req.user.set("oauth.twitter", profile.id);
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
                        "oauth.twitter": profile.id
                    }
                ]
            }).then((user) => {

                if (user) {
                    return done(null, user);
                }

                userModel.findOne({
                    username: profile.username
                }).then((user) => {

                    if (user) {
                        user = new userModel({
                            username: profile.username + "-" + String(profile.id).substr(0, 3),
                            password: crypto.randomBytes(20).toString('hex'),
                            "activation.active": true,
                            "oauth.twitter": profile.id
                        });

                    } else {
                        user = new userModel({
                            username: profile.username,
                            password: crypto.randomBytes(20).toString('hex'),
                            "activation.active": true,
                            "oauth.twitter": profile.id
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
            });
        }
    ));

    webserver.addRoute("get", "/auth/twitter", function (req, res, next) {
        req.session.returnTo = req.query.returnTo || "/";
        req.session.returnJSON = req.headers['user-agent'] === "APP-OAUTH";
        passport.authenticate('twitter')(req, res, next);
    });

    webserver.addRoute("get", "/auth/twitter/return", function (req, res, next) {
        passport.authenticate('twitter')(req, res, (err) => {
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
                var returnTo = req.session.returnTo;
                delete req.session.returnTo;
                return res.redirect(returnTo);
            }
        });
    });

}