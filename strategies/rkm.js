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

            const rkmUser = body.user;
            const userModel = Application.modules[Application.modules.auth.config.dbModuleName].getModel("user");

            return userModel.findOne({
                "oauth.rkm": rkmUser._id,
            }, function (err, connectedUser) {
                if (connectedUser) {
                    if (rkmUser.display) {
                        connectedUser.set("username", rkmUser.display);
                    }

                    if (rkmUser.email) {
                        connectedUser.set("email", rkmUser.email);
                    }
                    if(body.token){
                        connectedUser.set("_authtoken", body.token);
                        connectedUser.get("oauth").token = body.token;
                    }

                    return connectedUser.save(function (err) {
                        if (err) {
                            return done("internal_error");
                        }

                        return done(null, connectedUser);
                    });
                }

                return userModel.findOne({
                    "email": String(rkmUser.email).toLowerCase().trim(),
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
                noMail: config.noMail || false,
            },
        }, function (err, res, body) {
            if (err || res.statusCode !== 200) {
                return reject(new Error(err ? err.message : body));
            }

            return resolve(body);
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
                "customActivation": config.customActivation || false,
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


module.exports.saveUser = async function (_id, data, config) {
    const {email, username, password} = data;
    let errors = null;

    if (password) {
        try {
            await changePassword(_id, password, config);
        } catch (e) {
            if (!errors) {
                errors = {};
            }
            errors.password = "password error";
        }
    }
    if (username) {
        try {
            await changeUsername(_id, username, config);
        } catch (e) {
            if (!errors) {
                errors = {};
            }
            errors.username = "username error";
        }
    }
    if (email) {
        try {
            await changeEmail(_id, email, config);
        } catch (e) {
            if (!errors) {
                errors = {};
            }
            errors.email = "email error";
        }
    }

    if (errors) {
        let error = new Error();
        error.errors = errors;
        throw error;
    }

    return;
};

module.exports.validateCredentialsToken = async function (token, config) {
    return new Promise((resolve, reject) => {
        return request({
            url: config.host + "/api/auth-local/credentials-token",
            method: "post",
            body: {
                token: token

            },
            headers: {
                "rkm-authorization": config.apiKey,
            },
            json: true,
        }, function (err, res, body) {

            if (err || res.statusCode !== 200) {
                return reject(new Error("token.invalid"));
            }

            return resolve(body);
        });
    });
}

async function changePassword(_id, password, config) {
    return new Promise((resolve, reject) => {
        return request({
            url: config.host + "/api/auth-local/changePassword",
            method: "post",
            body: {
                userId: _id,
                password: password,

            },
            headers: {
                "rkm-authorization": config.apiKey,
            },
            json: true,
        }, function (err, res, body) {

            if (err || res.statusCode !== 200) {
                return reject(new Error("password.invalid"));
            }

            return resolve(body);
        });
    });
}

async function changeUsername(_id, username, config) {
    return new Promise((resolve, reject) => {
        return request({
            url: config.host + "/api/auth-local/changeUsername",
            method: "post",
            body: {
                userId: _id,
                username: username,

            },
            headers: {
                "rkm-authorization": config.apiKey,
            },
            json: true,
        }, function (err, res, body) {

            if (err || res.statusCode !== 200) {
                return reject(new Error("username.invalid"));
            }

            return resolve(body);
        });
    });
}

async function changeEmail(_id, email, config) {
    return new Promise((resolve, reject) => {
        return request({
            url: config.host + "/api/auth-local/changeEmail",
            method: "post",
            body: {
                userId: _id,
                email: email,

            },
            headers: {
                "rkm-authorization": config.apiKey,
            },
            json: true,
        }, function (err, res, body) {

            if (err || res.statusCode !== 200) {
                return reject(new Error("email.invalid"));
            }

            return resolve(body);
        });
    });
}

module.exports.changePassword = changePassword;
module.exports.changeUsername = changeUsername;
module.exports.changeEmail = changeEmail;
