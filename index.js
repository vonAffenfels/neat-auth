"use strict";

// @IMPORTS
var Application = require("neat-base").Application;
var Module = require("neat-base").Module;
var Tools = require("neat-base").Tools;
var passport = require("passport");
var Promise = require("bluebird");
var crypto = require("crypto");

module.exports = class Auth extends Module {

    static defaultConfig() {
        return {
            webserverModuleName: "webserver",
            dbModuleName: "database",
            enabled: {
                activation: false,
                terms: false
            },
            strategies: {
                local: true
            }
        }
    }

    init() {
        return new Promise((resolve, reject) => {
            this.log.debug("Initializing...");

            Application.modules[this.config.dbModuleName].registerModel("user", require("./models/user.js"));

            if (Application.modules[this.config.webserverModuleName]) {
                /*
                 Middleware
                 */
                Application.modules[this.config.webserverModuleName].addMiddleware(null, passport.initialize(), 0);
                Application.modules[this.config.webserverModuleName].addMiddleware(null, passport.session({
                    pauseStream: true
                }), 1);

                /*
                 Serialize User
                 */
                passport.serializeUser((user, done) => {
                    done(null, user.id);
                });

                /*
                 Deserialize user
                 */
                passport.deserializeUser((id, done) => {
                    var userModel = Application.modules[this.config.dbModuleName].getModel("user");

                    userModel
                        .findOne({
                            _id: id
                        })
                        .then((user) => {
                            if (!user) {
                                return done(null, false);
                            }

                            userModel.update({
                                _id: id
                            }, {
                                $set: {
                                    lastActivity: new Date()
                                }
                            }).then(() => {
                                done(null, user);
                            }, (err) => {
                                done(err);
                            });

                        }, (err) => {
                            done(err);
                        });
                });

                if (this.config.strategies.local) {
                    require("./strategies/local.js")(passport, this.config.strategies.local, Application.modules[this.config.webserverModuleName]);
                }

                Application.modules[this.config.webserverModuleName].addRoute("post", "/auth/register", (req, res) => {
                    this.register(req.body).then((user) => {
                        res.json(user);
                    }, (err) => {
                        res.status(400);
                        res.json(err);
                    });
                });

                Application.modules[this.config.webserverModuleName].addRoute("post", "/auth/activate-account", (req, res) => {
                    this.activate(req.body.token).then((user) => {
                        res.json(user);
                    }, (err) => {
                        res.status(400);
                        res.json(err);
                    });
                });

                Application.modules[this.config.webserverModuleName].addRoute("post", "/auth/resend-activation", (req, res) => {
                    this.resendActivationMail(req.body.username).then((user) => {
                        res.json(user);
                    }, (err) => {
                        res.status(400);
                        res.json(err);
                    });
                });

                Application.modules[this.config.webserverModuleName].addRoute("post", "/auth/login", (req, res) => {
                    passport.authenticate("local", (err, user, info) => {
                        if (!user) {
                            res.status(400);
                            return res.json({
                                code: "invalid_credentials",
                                message: "Invalid credentials"
                            });
                        }

                        if (!user.activation.active && this.config.enabled.activation) {
                            res.status(400);
                            return res.json({
                                code: "not_activated",
                                message: "Please activate your account"
                            });
                        }

                        if (user.banned) {
                            res.status(400);
                            return res.json({
                                code: "banned",
                                message: "Your account has been banned. If you believe this to be a mistake, please contact us"
                            });
                        }

                        req.logIn(user, function (err) {
                            if (req.body.remember) {
                                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000 * 12; // Cookie expires after one year
                            } else {
                                req.session.cookie.expires = false; // Cookie expires at end of session
                            }

                            if (err) {
                                res.status(500);
                                return res.err(err);
                            }

                            Application.emit("user.login", {
                                user: user
                            });

                            res.json(user);
                        });
                    })(req, res)
                });

                Application.modules[this.config.webserverModuleName].addRoute("post", "/auth/logout", (req, res) => {
                    if (!req.user) {
                        return res.json({
                            success: true
                        });
                    }

                    req.logout();
                    return res.json({
                        success: true
                    });
                });

                Application.modules[this.config.webserverModuleName].addRoute("post", "/auth/current", (req, res) => {
                    if (!req.user) {
                        res.status(400);
                        return res.json({
                            code: "not_loggedin",
                            message: "Not Logged in"
                        });
                    }

                    res.json(req.user);
                });

                Application.modules[this.config.webserverModuleName].addRoute("post", "/auth/reset-password", (req, res) => {
                    var user = Application.modules[this.config.dbModuleName].getModel("user");
                    user.findOne({
                        "email": req.body.email
                    }).then((doc) => {
                        if (doc) {
                            doc.resetPassword();
                            Application.emit("user.reset", {
                                user: doc
                            });
                            res.json({
                                success: true
                            });
                        } else {
                            res.status(400);
                            return res.json({
                                code: "email_not_found",
                                message: "User not found"
                            });
                        }

                    }, (err) => {
                        res.status(400);
                        res.err(err);
                    });
                });

                Application.modules[this.config.webserverModuleName].addRoute("post", "/auth/do-reset-password", (req, res) => {
                    if (!req.body.token) {
                        res.status(400);
                        return res.json({
                            code: "token_invalid",
                            message: "Password reset token invalid"
                        });
                    }

                    if (req.body.password !== req.body.password2) {
                        res.status(400);
                        return res.json({
                            code: "password_mismatch",
                            message: "Passwords do not match"
                        });
                    }

                    var model = Application.modules[this.config.dbModuleName].getModel("user");
                    model.findOne({
                        "reset.token": req.body.token
                    }).then((doc) => {

                        if (!doc) {
                            res.status(400);
                            return res.json({
                                code: "token_invalid",
                                message: "Password reset token invalid"
                            });
                        }

                        doc.password = req.body.password;
                        doc.reset.active = false;
                        doc.reset.token = null;
                        doc.save().then(() => {

                            req.logIn(doc, function (err) {
                                req.session.cookie.expires = false;

                                if (err) {
                                    res.status(500);
                                    return res.err(err);
                                }

                                Application.emit("user.login", {
                                    user: doc
                                });

                                res.json(doc);
                            });
                        }, (err) => {
                            res.status(400);
                            res.err(err);
                        });
                    })
                });
            }

            resolve(this);
        });
    }

    hasPermission(req, modelName, action, doc, query) {
        try {
            var model = Application.modules[this.config.dbModuleName].getModel(modelName);
        } catch (e) {
            return false;
        }

        if (req.user && req.user.admin) {
            return true;
        }

        if (model.schema.options.permissions) {
            if (model.schema.options.permissions[action] === true) {
                return true;
            }

            if (model.schema.options.permissions[action] === "own") {
                if (!req.user) {
                    return false;
                }

                if (doc._createdBy + "" == req.user._id + "" || doc._id + "" == req.user._id + "") {
                    return true;
                }
            }

            if (model.schema.options.permissions[action] === false) {
                if (!req.user || !req.user.permissions) {
                    return false;
                }

                if (req.user.permissions.indexOf(modelName + "/" + action) !== -1) {
                    return true;
                }

                if (req.user.permissions.indexOf(modelName) !== -1) {
                    return true;
                }
            }
        }

        return false;
    }

    register(data) {
        return new Promise((resolve, reject) => {
            var userModel = Application.modules[this.config.dbModuleName].getModel("user");
            var user = new userModel(data);

            if (data.password !== data.password2) {
                return reject({
                    password: "The passwords do not match"
                });
            }

            return user.save().then(() => {
                Application.emit("user.register", {
                    user: user
                });

                resolve(user);
            }, reject);
        })
    }

    activate(token) {
        return new Promise((resolve, reject) => {
            var userModel = Application.modules[this.config.dbModuleName].getModel("user");

            if (!token) {
                return reject({
                    code: "token_missing",
                    message: "Please supply an activation token"
                });
            }

            userModel.findOne({
                "activation.token": token
            }).then((doc) => {
                if (!doc) {
                    return reject({
                        code: "invalid_token",
                        message: "The supplied token is invalid"
                    });
                }

                if (doc.activation.active) {
                    return reject({
                        code: "invalid_token",
                        message: "The supplied token is invalid"
                    });
                }

                doc.set("activation.active", true);

                doc.save({
                    validateBeforeSave: false
                }).then(() => {
                    Application.emit("user.activated", {
                        user: doc
                    });

                    resolve(doc);
                }, (err) => {
                    return reject(err);
                });
            });
        })
    }

    resendActivationMail(usernameOrEmail) {
        return new Promise((resolve, reject) => {
            var userModel = Application.modules[this.config.dbModuleName].getModel("user");
            userModel
                .findOne({
                    $or: [
                        {
                            username: new RegExp("^" + Tools.escapeForRegexp(usernameOrEmail) + "$", "i")
                        },
                        {
                            email: new RegExp("^" + Tools.escapeForRegexp(usernameOrEmail) + "$", "i")
                        }
                    ]
                })
                .exec()
                .then((user) => {
                    if (!user) {
                        return reject({
                            code: "user_not_found",
                            message: "User not found"
                        });
                    }

                    Application.emit("user.register", {
                        user: user
                    });

                    resolve();
                }, (err) => {
                    reject(err);
                });
        });
    }
}
