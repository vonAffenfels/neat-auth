"use strict";

const strategy = require("passport-local");
const Tools = require("neat-base").Tools;
const Application = require("neat-base").Application;
const Promise = require("bluebird");

module.exports = function (passport, config, webserver) {
    passport.use('local', new strategy((username, password, done) => {
        let userModel = Application.modules[Application.modules.auth.config.dbModuleName].getModel("user");

        let ssoSync = Promise.resolve(true);
        if (Application.modules.auth.sso) {
            ssoSync = Application.modules.auth.sso.syncUserByEmail(username);
        }

        ssoSync.then((val) => {
            let ssoSyncUsername = Promise.resolve();

            if (!val && Application.modules.auth.sso) {
                ssoSyncUsername = Application.modules.auth.sso.syncUserByUsername(username);
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