var strategy = require("passport-local");
var Tools = require("neat-base").Tools;
var Application = require("neat-base").Application;

module.exports = function (passport, config, webserver) {
    passport.use('local', new strategy((username, password, done) => {
        var userModel = Application.modules[Application.modules.auth.config.dbModuleName].getModel("user");
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
    }));
}