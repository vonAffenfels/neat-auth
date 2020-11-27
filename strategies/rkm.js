"use strict";

const strategy = require("passport-local");
const Tools = require("neat-base").Tools;
const Application = require("neat-base").Application;
const Promise = require("bluebird");
const request = require("request");
const crypto = require("crypto");

module.exports = function (passport, config, webserver) {

    passport.use('local', new strategy((username, password, done) => {
        return request({
            url: config.host + "/api/auth-local/login",
            method: "post",
            form: {
                client: config.client,
                username: username,
                password: password,
            },
            json: true,
        }, function (err, res, body) {

            let invalidCredentials = false;

            if (err) {
                invalidCredentials = true;
                return done("invalid_credentials");
            } else if (res.statusCode !== 200) {
                if (body.activation) {
                    return done("not_activated");
                }

                invalidCredentials = true;
            }

            if (invalidCredentials) {
                return request({
                    url: config.host + "/api/auth-local/hasCredentials",
                    method: "post",
                    form: {
                        username: username,
                    },
                    json: true,
                }, function (err, res, body) {
                    if (body && body.exists && !body.hasCredentials) {
                        return done("new_password");
                    }

                    return done("invalid_credentials");
                });
            }

            const userModel = Application.modules[Application.modules.auth.config.dbModuleName].getModel("user");

            return userModel.findOne({
                "oauth.rkm": rkmUser._id,
            }, function (err, connectedUser) {
                if (connectedUser) {
                    if (rkmUser.display) {
                        connectedUser.set("display", rkmUser.display);
                    }

                    if (rkmUser.email) {
                        connectedUser.set("email", rkmUser.email);
                    }

                    return connectedUser.save(function (err) {
                        if (err) {
                            return done("internal_error");
                        }

                        return done(null, connectedUser);
                    });
                }

                return userModel.findOne({
                    "email": rkmUser.email,
                }, function (err, unconnectedUser) {
                    if (err) {
                        return done("internal_error");
                    }

                    if (!unconnectedUser) {
                        unconnectedUser = new userModel({
                            username: rkmUser.display,
                            email: rkmUser.email,
                        });
                    }

                    unconnectedUser.set("oauth.rkm", rkmUser._id);

                    if (rkmUser.display) {
                        unconnectedUser.set("username", rkmUser.display);
                    }

                    if (rkmUser.email) {
                        unconnectedUser.set("email", rkmUser.email);
                    }

                    return unconnectedUser.save(function (err) {
                        if (err) {
                            return done("internal_error");
                        }

                        return done(null, unconnectedUser);
                    });
                });
            });
        });
    }));

};

module.exports.resetPassword = async function (email, config) {
    return new Promise((resolve, reject) => {
        return request({
            url: config.host + "/api/auth-local/pwreset/init",
            method: "post",
            form: {
                client: config.client,
                email: email,
            },
        }, function (err, res, body) {
            if (err || res.statusCode !== 200) {
                return reject(new Error(err ? err.message : body));
            }

            return resolve();
        });
    });
};

module.exports.register = async function (email, username, password, config) {
    return new Promise((resolve, reject) => {
        return request({
            url: config.host + "/api/auth-local/register",
            method: "post",
            body: {
                client: config.client,
                "display": username,
                "email": email,
                "username": username,
                "password": password,
            },
            json: true,
        }, function (err, res, body) {

            if (err || res.statusCode !== 200) {
                const error = new Error(err ? err.message : body);

                if (body) {
                    error.errors = body;
                } else {
                    error.errors = {username: err.message};
                }

                return reject(error);
            }

            return resolve(body);
        });
    });
};