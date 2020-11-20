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
        }, function (err, res, body) {
            if (err) {
                return done("invalid_credentials");
            }

            if (res.statusCode !== 200) {
                return done("invalid_credentials");
            }

            try {
                body = JSON.parse(body);
            } catch (e) {
                return done("internal_error");
            }

            const rkmUser = body.user;
            const userModel = Application.modules[Application.modules.auth.config.dbModuleName].getModel("user");

            return userModel.findOne({
                "oauth.rkm": rkmUser._id,
            }, function (err, connectedUser) {

                if (connectedUser) {
                    if (rkmUser.username) {
                        connectedUser.set("username", rkmUser.username);
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
                            username: rkmUser.username,
                            email: rkmUser.email,
                        });
                    }

                    unconnectedUser.set("oauth.rkm", rkmUser._id);

                    if (rkmUser.username) {
                        unconnectedUser.set("username", rkmUser.username);
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
                return reject(new Error(err.message || body));
            }

            return resolve();
        });
    });
};
