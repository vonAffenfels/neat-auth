"use strict";

// @IMPORTS
const Application = require("neat-base").Application;
const Module = require("neat-base").Module;
const Tools = require("neat-base").Tools;
const passport = require("passport");
const Promise = require("bluebird");
const crypto = require("crypto");
const passwordHash = require('password-hash');

module.exports = class Auth extends Module {

    static defaultConfig() {
        return {
            webserverModuleName: "webserver",
            ssoModuleName: "sso",
            populateUser: [],
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

            this.sso = Application.modules[this.config.ssoModuleName];

            Application.modules[this.config.dbModuleName].registerModel("user", require("./models/user.js"));
            Application.modules[this.config.dbModuleName].registerModel("termversion", require("./models/termversion.js"));

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
                        .populate(this.config.populateUser)
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
                if (this.config.strategies.facebook) {
                    require("./strategies/facebook.js")(passport, this.config.strategies.facebook, Application.modules[this.config.webserverModuleName]);
                }

                if (this.config.strategies.token) {
                    Application.modules[this.config.webserverModuleName].addMiddleware((req, res, next) => {
                        let token = req.headers["neat-auth"] || null;
                        let userModel = Application.modules[Application.modules.auth.config.dbModuleName].getModel("user");

                        if (!token) {
                            return next();
                        }

                        userModel
                            .findOne({
                                _authtoken: token
                            })
                            .populate(this.config.populateUser)
                            .exec()
                            .then((doc) => {
                                if (!doc) {
                                    return next();
                                }

                                if (doc.banned) {
                                    res.status(400);
                                    return res.json({
                                        code: "banned",
                                        message: "Your account has been banned. If you believe this to be a mistake, please contact us."
                                    });
                                }

                                req.logIn(doc, function (err) {
                                    Application.emit("user.tokenlogin", {
                                        user: doc
                                    });
                                    return next();
                                });
                            }, (err) => {
                                return next();
                            })
                    })
                }

                Application.modules[this.config.webserverModuleName].addRoute("post", "/auth/register", (req, res) => {
                    this.register(req.body).then((user) => {
                        res.json(user);
                    }, (err) => {
                        res.status(400);
                        res.err(err);
                    });
                });

                Application.modules[this.config.webserverModuleName].addRoute("post", "/auth/activate-account", (req, res) => {
                    this.activate(req.body.token).then((user) => {
                        res.json(user);
                    }, (err) => {
                        res.status(400);
                        res.err(err);
                    });
                });

                Application.modules[this.config.webserverModuleName].addRoute("post", "/auth/resend-activation", (req, res) => {
                    this.resendActivationMail(req.body).then((user) => {
                        res.json(user);
                    }, (err) => {
                        res.status(400);
                        res.err(err);
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

                        let userPopulateProm = Promise.resolve();
                        if (this.config.populateUser && this.config.populateUser.length) {
                            userPopulateProm = user.populate(this.config.populateUser).execPopulate();
                        }

                        userPopulateProm.then(() => {
                            let acceptProm = Promise.resolve();

                            if (req.body.termsAndConditionsAccepted && this.config.enabled.terms) {
                                user.acceptTermsAndConditions();
                                acceptProm = user.save();
                            }

                            return acceptProm;
                        }).then(() => {
                            return user.checkTermsAndConditions();
                        }).then(() => {

                            if (!user.activation.active && this.config.enabled.activation && !this.config.allowLoginWithoutActivation) {
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
                                    message: "Your account has been banned. If you believe this to be a mistake, please contact us."
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
                                    user: user,
                                    data: req.body
                                });

                                res.json(user);
                            });
                        }, () => {
                            res.status(400);
                            return res.json({
                                code: "terms_outdated",
                                message: "You have to accept the current terms and conditions."
                            });
                        })
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

                    if (!req.user || (!this.config.allowLoginWithoutActivation && (!req.user.activation || !req.user.activation.active))) {
                        res.status(400);
                        return res.json({
                            code: "not_loggedin",
                            message: "Not Logged in"
                        });
                    }

                    if (!this.config.allowLoginWithoutTerms) {
                        return req.user.checkTermsAndConditions().then(() => {
                            res.json(req.user.toObject({virtuals: true, getters: true}));
                        }, (err) => {
                            req.logout();
                            return res.json({
                                code: "terms_outdated",
                                message: "You have to accept the current terms and conditions."
                            });
                        })
                    } else {
                        res.json(req.user.toObject({virtuals: true, getters: true}));
                    }
                });

                Application.modules[this.config.webserverModuleName].addRoute("post", "/auth/getCurrentTermsAndConditions", (req, res) => {
                    let termsModel = Application.modules[this.config.dbModuleName].getModel("termversion");
                    return termsModel.findOne().sort({
                        _createdAt: -1
                    }).select({content: req.body.content || false, versions: false}).then((currentTermsVersion) => {
                        res.json(currentTermsVersion);
                    });
                });

                Application.modules[this.config.webserverModuleName].addRoute("post", "/auth/reset-password", (req, res) => {
                    var user = Application.modules[this.config.dbModuleName].getModel("user");

                    if (!req.body.email) {
                        return res.status(400).json({
                            code: "email_missing",
                            message: "Email missing"
                        })
                    }

                    user.findOne({
                        "email": req.body.email.toLowerCase().trim()
                    }).then((doc) => {
                        if (doc) {
                            doc.resetPassword();
                            Application.emit("user.reset", {
                                user: doc,
                                data: req.body
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
                                    user: doc,
                                    data: req.body
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
            } else if (model.schema.options.permissions[action] === "auth") {
                if (req.user) {
                    return true;
                }
            } else {
                if (!req.user) {
                    return false;
                }

                if (req.user.hasPermission(modelName + "." + action)) {
                    return true;
                }

                if (req.user.hasPermission(modelName)) {
                    return true;
                }

                if (model.schema.options.permissions[action] === "own") {
                    if (req.user.isOwnerOfDoc(doc)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    register(data) {
        return new Promise((resolve, reject) => {
            let userModel = Application.modules[this.config.dbModuleName].getModel("user");
            let user = new userModel(data);

            if (data.password !== data.password2) {
                return reject({
                    password: "The passwords do not match"
                });
            }

            if (!data.termsAndConditionsAccepted && this.config.enabled.terms) {
                return reject({
                    termsAndConditionsAccepted: "Please accept our terms and conditions"
                });
            }

            let ssoSync = Promise.resolve(true);
            if (this.sso) {
                ssoSync = this.sso.syncUserByEmail(data.email, data.password);
            }

            ssoSync.then(() => {
                let ssoSyncUsername = Promise.resolve();

                if (this.sso) {
                    ssoSyncUsername = this.sso.syncUserByUsername(data.username, data.password);
                }

                return ssoSyncUsername;
            }).then(() => {
                return user.acceptTermsAndConditions().save().then(() => {
                    Application.emit("user.register", {
                        user: user,
                        data: data
                    });

                    resolve(user);
                }, reject);
            });
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
                        code: "already_used",
                        message: "The supplied token has already been used"
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

    resendActivationMail(data) {
        let usernameOrEmail = data.username;
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
                        user: user,
                        data: data
                    });

                    resolve();
                }, (err) => {
                    reject(err);
                });
        });
    }

    modifySchema(modelName, schema) {
        let selfModule = this;

        if (modelName === "user") {
            schema.path('username').validate(function (value, cb) {
                var self = this;

                try {
                    var regexp = new RegExp("^" + value + "$", 'i');
                } catch (e) {
                    cb(false);
                }

                Application.modules[selfModule.config.dbModuleName].getModel("user").findOne({
                    username: regexp
                }).read("primary").then((user) => {
                    if ((user && user.id !== self.id)) {
                        return cb(false);
                    }
                    cb(true);
                }, () => {
                    cb(false);
                });
            }, 'username duplicated');

            schema.path('username').validate(function (value) {
                if (value.length < 3) {
                    return false;
                }

                return true;
            }, 'username is too short 3-30');

            schema.path('password').validate(function (value) {
                if (value.length < 6) {
                    return false;
                }

                return true;
            }, 'password is too short, should be at least 6 characters long');

            schema.path('username').validate(function (value) {
                if (value.length > 30) {
                    return false;
                }

                return true;
            }, 'username is too long 3-30');

            schema.path('username').validate(function (value) {
                if (value.length === 0) {
                    return false;
                }

                return true;
            }, 'username is empty');

            schema.path('email').validate(function (value, cb) {
                var self = this;
                try {
                    var regexp = new RegExp("^" + value + "$", 'i');
                } catch (e) {
                    cb(false);
                }
                Application.modules[selfModule.config.dbModuleName].getModel("user").findOne({
                    email: regexp
                }).read("primary").then((user) => {
                    if ((user && user.id !== self.id)) {
                        return cb(false);
                    }

                    cb(true);
                }, () => {
                    return cb(false);
                });
            }, 'email duplicate');

            schema.path('termsAndConditions').validate(function (value, cb) {
                if (!selfModule.config.enabled.terms) {
                    return cb(true);
                }

                // in case the user is being created (by an admin/user with permissions in the backend) dont check terms
                if (this._createdBy + "" !== this._id + "" && !this._updatedBy) {
                    return cb(true);
                }

                // in case the user is being updated (by an admin/user with permissions in the backend) dont check terms
                if (this._updatedBy + "" !== this._id + "") {
                    return cb(true);
                }

                if (!value || !value.length) {
                    return cb(false);
                }

                let termsModel = Application.modules[selfModule.config.dbModuleName].getModel("termversion");
                return termsModel.findOne().sort({
                    _createdAt: -1
                }).then((currentTermsVersion) => {

                    for (let i = 0; i < value.length; i++) {
                        let acceptedTerms = value[i];

                        if (acceptedTerms.version === currentTermsVersion._id) {
                            return cb(true);
                        }
                    }

                    cb(false);
                });
            }, 'termsAndConditions invalid');

            schema.methods.checkPassword = function (val) {
                return passwordHash.verify(val, this.password);
            }

            schema.methods.resetPassword = function () {
                const userModel = Application.modules[selfModule.config.dbModuleName].getModel("user");
                let token = crypto.randomBytes(24).toString("hex");
                this.set("reset.token", token);
                this.set("reset.active", true);
                return userModel.update({
                    _id: this.get("_id")
                }, {
                    $set: {
                        "reset.token": token,
                        "reset.active": true
                    }
                }).exec()
            }

            schema.methods.acceptTermsAndConditions = function () {
                this._acceptTermsAndConditions = true;
                return this;
            }

            schema.methods.isOwnerOfDoc = function (doc) {
                if (!doc) {
                    return false;
                }

                // was created by user => ok
                if (doc._createdBy + "" == this._id + "") {
                    return true;
                }

                // IS the user itself => ok
                if (doc._id + "" == this._id + "") {
                    return true;
                }

                return false;
            }

            schema.methods.hasPermission = function (val) {
                // admin, access to everything
                if (this.admin) {
                    return true;
                }

                if (!this.permissions || !this.permissions.length) {
                    return false;
                }

                if (val instanceof Array) {
                    for (let i = 0; i < val.length; i++) {
                        let perm = val[i];

                        // if a permission is found
                        if (this.permissions.indexOf(perm) !== -1) {
                            return true;
                        }
                    }

                    // no permission found
                    return false;
                } else {
                    if (this.permissions.indexOf(val) !== -1) {
                        // permission found
                        return true;
                    }
                }

                return false;
            }

            schema.methods.checkTermsAndConditions = function () {
                return new Promise((resolve, reject) => {

                    if (!selfModule.config.enabled.terms) {
                        return resolve();
                    }

                    let termsModel = Application.modules[selfModule.config.dbModuleName].getModel("termversion");
                    return termsModel.findOne().sort({
                        _createdAt: -1
                    }).then((currentTermsVersion) => {

                        if (!currentTermsVersion) {
                            return reject(new Error("invalid version"));
                        }

                        for (let i = 0; i < this.termsAndConditions.length; i++) {
                            let acceptedTerms = this.termsAndConditions[i];

                            if (acceptedTerms.version === currentTermsVersion._id) {
                                return resolve();
                            }
                        }

                        return reject(new Error("invalid version"));
                    });
                });
            }

            schema.pre("validate", function (next) {
                if (this._acceptTermsAndConditions && selfModule.config.enabled.terms) {

                    let termsModel = Application.modules[selfModule.config.dbModuleName].getModel("termversion");
                    return termsModel.findOne().sort({
                        _createdAt: -1
                    }).then((currentTermsVersion) => {

                        if (!currentTermsVersion) {
                            return next();
                        }

                        if (!this.termsAndConditions) {
                            this.termsAndConditions = [];
                        }

                        this.termsAndConditions.push({
                            version: currentTermsVersion._id
                        });

                        next();
                    }, () => {
                        return next();
                    });
                } else {
                    next();
                }
            });
        }

    }
}
