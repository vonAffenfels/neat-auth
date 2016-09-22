var strategy = require("passport-reddit").Strategy;
var Tools = require("neat-base").Tools;
var mongoose = require("mongoose");

module.exports = function (passport, config, webserver) {

    passport.use(new strategy({
            clientID: config.redditKey,
            clientSecret: config.redditSecret,
            callbackURL: config.redditReturn,
            successReturnToOrRedirect: true,
            passReqToCallback: true
        },
        function (req, token, tokenSecret, profile, done) {
            var userModel = mongoose.model("user");

            if (req.user) {
                req.user.set("oauth.reddit", profile.id);
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
                        "oauth.reddit": profile.id
                    }
                ]
            }).then((user) => {

                if (user) {
                    return done(null, user);
                }

                userModel.findOne({
                    username: profile.name
                }).then((user) => {

                    if (user) {
                        user = new userModel({
                            username: profile.name + "-" + String(profile.id).substr(0, 3),
                            password: crypto.randomBytes(20).toString('hex'),
                            "activation.active": true,
                            "oauth.reddit": profile.id
                        });
                    } else {
                        user = new userModel({
                            username: profile.name,
                            password: crypto.randomBytes(20).toString('hex'),
                            "activation.active": true,
                            "oauth.reddit": profile.id
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

    webserver.addRoute("get", "/auth/reddit", (req, res, next) => {
        req.session.returnTo = req.query.returnTo || "/";
        req.session.returnJSON = req.headers['user-agent'] === "APP-OAUTH";
        req.session.state = crypto.randomBytes(32).toString('hex');
        passport.authenticate('reddit', {
            state: req.session.state,
            duration: 'permanent'
        })(req, res, next);
    });

    webserver.addRoute("get", "/auth/reddit/return", (req, res, next) => {
        if (req.query.state == req.session.state) {
            passport.authenticate('reddit')(req, res, (err) => {
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
        } else {
            res.redirect("/");
        }
    });

}