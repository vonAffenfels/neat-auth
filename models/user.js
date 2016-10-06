"use strict";

// @IMPORTS
var mongoose = require("mongoose");
var crypto = require("crypto");
var passwordHash = require('password-hash');
var Promise = require("bluebird");

var schema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        index: true,
        set: function (val) {
            return val.toLowerCase().trim();
        }
    },

    oauth: {
        twitter: String,
        reddit: String,
        steam: String,
        facebook: String,
        google: String
    },

    admin: {
        type: Boolean,
        default: false
    },

    username: {
        type: String,
        required: true,
        index: true,
        set: function (val) {
            return val.trim();
        }
    },

    password: {
        type: String,
        required: true,
        toJSON: false,
        index: true,
        set: function (val) {
            if (!val) {
                return val;
            }

            val = String(val).trim();

            if (!val) {
                return val;
            }

            if (passwordHash.isHashed(val)) {
                return val;
            } else {
                return passwordHash.generate(val);
            }
        }
    },

    termsAndConditions: {
        accepted: {
            type: Boolean,
            default: null,
            required: true
        },
        acceptanceDate: {
            type: Date
        }
    },

    activation: {
        active: {
            type: Boolean,
            default: false
        },
        token: {
            type: String,
            required: false,
            default: function () {
                return crypto.randomBytes(48).toString("hex");
            }
        }
    },

    lastActivity: {
        type: Date,
        default: function () {
            return new Date();
        }
    },

    reset: {
        active: {
            type: Boolean,
            default: false
        },
        token: {
            type: String,
            required: false
        }
    },

    permissions: [
        String
    ]
}, {
    permissions: {
        find: true,
        findOne: true,
        count: true,
        save: "own",
        remove: "own"
    },
    toJSON: {
        virtuals: true,
        transform: function (doc) {
            var obj = doc.toJSON({
                transform: false
            });

            delete obj.password;

            if (obj.activation) {
                delete obj.activation.token;
            }

            if (obj.reset) {
                delete obj.reset.token;
            }

            return obj;
        }
    },
    toObject: {
        virtuals: true
    }
});

schema.path('username').validate(function (value, cb) {
    var self = this;

    try {
        var regexp = new RegExp("^" + value + "$", 'i');
    } catch (e) {
        cb(false);
    }

    mongoose.model("user").findOne({
        username: regexp
    }).then((user) => {
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

schema.path('termsAndConditions.accepted').validate(function (value) {
    return value;
}, 'You must accept our Terms and Conditions');

schema.path('email').validate(function (value, cb) {
    var self = this;
    try {
        var regexp = new RegExp("^" + value + "$", 'i');
    } catch (e) {
        cb(false);
    }
    mongoose.model("user").findOne({
        email: regexp
    }).then((user) => {
        if ((user && user.id !== self.id)) {
            return cb(false);
        }

        cb(true);
    }, () => {
        return cb(false);
    });
}, 'email duplicate');

schema.methods.checkPassword = function (val) {
    return passwordHash.verify(val, this.password);
}

schema.methods.loadChildren = function () {
    return new Promise((resolve, reject) => {
        resolve();
    });
}

schema.methods.resetPassword = function () {
    this.reset.token = crypto.randomBytes(24).toString("hex");
    this.reset.active = true;
    this.save(function (err) {
        if (!err) {
            return;
        } else {
            return err;
        }
    });
}

module.exports = schema;
