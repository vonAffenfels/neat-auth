var strategy = require("passport-local");
var Tools = require("neat-base").Tools;
var mongoose = require("mongoose");

module.exports = function (passport, config, webserver) {
    passport.use('local', new strategy((username, password, done) => {
        var userModel = mongoose.model("user");
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
            .cache(false)
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