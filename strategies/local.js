"use strict";

const strategy = require("passport-local");
const Tools = require("neat-base").Tools;
const Application = require("neat-base").Application;
const Promise = require("bluebird");
const request = require("request");
const crypto = require("crypto");

module.exports = function (passport, config, webserver) {

    function oauthresponseHandler(accessToken, refreshToken, profile, cb) {
        request(config.password_grant.dataUrl + accessToken, function (err, res, dpvUser) {

            try {
                dpvUser = JSON.parse(dpvUser);
            } catch (e) {
                return cb("invalid_credentials");
            }

            if (!dpvUser) {
                return cb("invalid_credentials");
            }

            if (err) {
                return cb(err);
            }

            let userModel = Application.modules[Application.modules.auth.config.dbModuleName].getModel("user");

            userModel.findOne({
                "oauth.password": dpvUser.id
            }, function (err, connectedUser) {
                if (connectedUser) {
                    if (dpvUser.nickname) {
                        connectedUser.set("username", dpvUser.nickname);
                    }
                    if (dpvUser.email) {
                        connectedUser.set("email", dpvUser.email);
                    }
                    return connectedUser.save(function (err) {
                        if (err) {
                            return cb(err);
                        }

                        return cb(null, connectedUser);
                    });
                }

                userModel.findOne({
                    "email": dpvUser.email
                }, function (err, unconnectedUser) {
                    if (err) {
                        return cb(err);
                    }

                    if (!unconnectedUser) {
                        var hashedUsername = crypto.createHash('md5').update(dpvUser.username || dpvUser.email).digest("hex");
                        unconnectedUser = new userModel({
                            username: dpvUser.nickname || hashedUsername.substr(0, 12),
                            password: hashedUsername,
                            email: dpvUser.email
                        });
                    }

                    unconnectedUser.set("oauth.password", dpvUser.id);
                    if (dpvUser.nickname) {
                        unconnectedUser.set("username", dpvUser.nickname);
                    }
                    if (dpvUser.email) {
                        unconnectedUser.set("email", dpvUser.email);
                    }

                    unconnectedUser.save(function (err) {
                        console.log(err);
                        if (err) {
                            return cb(err);
                        }

                        return cb(null, unconnectedUser);
                    });
                });
            });
        });
    }

    if (config !== true && config.password_grant) {

        passport.use('local', new strategy((username, password, done) => {
            return request({
                url: config.password_grant.tokenURL,
                method: "get",
                qs: {
                    grant_type: "password",
                    username: username,
                    password: password,
                    client_id: config.password_grant.clientID,
                    client_secret: config.password_grant.clientSecret
                }
            }, function (err, res, body) {

                if (err) {
                    return done("invalid_credentials");
                }

                try {
                    body = JSON.parse(body);

                    if (body.error) {
                        return done("invalid_credentials");
                    }
                } catch (e) {
                    return done("invalid_credentials");
                }

                oauthresponseHandler(body.access_token, body.refresh_token, null, function (err, user) {

                    if (err) {
                        return done(err);
                    }

                    done(null, user, {});
                });
            });
        }));

    } else {

        passport.use('local', new strategy((username, password, done) => {
            let userModel = Application.modules[Application.modules.auth.config.dbModuleName].getModel("user");

            if (typeof username === "string") {
                username = username.trim();
            } else {
                username = null;
            }

            if (typeof password === "string") {
                password = password.trim();
            } else {
                password = null;
            }

            let ssoSync = Promise.resolve(true);
            if (Application.modules.auth.sso) {
                ssoSync = Application.modules.auth.sso.syncUserByEmail(username, password);
            }

            ssoSync.then((val) => {
                let ssoSyncUsername = Promise.resolve();

                if (!val && Application.modules.auth.sso) {
                    ssoSyncUsername = Application.modules.auth.sso.syncUserByUsername(username, password);
                }

                return ssoSyncUsername;
            }).then(() => {
                userModel
                    .findOne({
                        $or: [
                            {
                                username: new RegExp("^" + Tools.escapeForRegexp(username) + "$", "i")
                            },
                            {
                                email: new RegExp("^" + Tools.escapeForRegexp(username) + "$", "i")
                            }
                        ]
                    })
                    .exec()
                    .then((user) => {
                        if (!user) {
                            return done();
                        }

                        if (user.checkPassword(password)) {
                            done(null, user);
                        } else {
                            done("invalid_credentials");
                        }
                    }, (err) => {
                        done(err);
                    });
            });
        }));
    }
}