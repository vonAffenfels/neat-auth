var strategy = require("passport-steam").Strategy;
var Tools = require("neat-base").Tools;
var Application = require("neat-base").Application;

module.exports = function (passport, config, webserver) {

    passport.use(new strategy({
            returnURL: config.steamReturn,
            realm: config.steamRealm,
            apiKey: config.steam,
            successReturnToOrRedirect: true,
            passReqToCallback: true
        },
        function (req, identifier, profile, done) {
            var userModel = Application.modules[Application.modules.auth.config.dbModuleName].getModel("user");

            if (req.user) {
                req.user.set("oauth.steam", identifier);
                return req.user.save({
                    validateBeforeSave: false
                }).then(() => {
                    return done(null, req.user);
                });
            }

            userModel.findOne({
                $or: [
                    {
                        openId: identifier
                    },
                    {
                        "oauth.steam": identifier
                    }
                ]
            }).then((user) => {

                if (user) {
                    return done(null, user);
                }

                userModel.findOne({
                    username: profile._json.personaname
                }).then((user) => {

                    if (user) {
                        user = new userModel({
                            username: profile._json.personaname + "-" + String(profile._json.steamid).substr(0, 3),
                            password: crypto.randomBytes(20).toString('hex'),
                            "activation.active": true,
                            "oauth.steam": identifier
                        });

                    } else {
                        user = new userModel({
                            username: profile._json.personaname,
                            password: crypto.randomBytes(20).toString('hex'),
                            "activation.active": true,
                            "oauth.steam": identifier
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

    webserver.addRoute("get", "/auth/steam", function (req, res, next) {
        req.session.returnTo = req.query.returnTo || "/";
        req.session.returnJSON = req.headers['user-agent'] === "APP-OAUTH";
        passport.authenticate('steam')(req, res, next);
    });

    webserver.addRoute("get", "/auth/steam/return", function (req, res, next) {
        passport.authenticate('steam')(req, res, (err) => {
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