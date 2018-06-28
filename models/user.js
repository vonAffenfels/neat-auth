"use strict";

// @IMPORTS
const Application = require("neat-base").Application;
const crypto = require("crypto");
const passwordHash = require('password-hash');
const Promise = require("bluebird");
const mongoose = require('mongoose');

let schema = new mongoose.Schema({
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
        google: String,
        password: String
    },

    admin: {
        permission: false,
        type: Boolean,
        default: false
    },

    username: {
        permission: false,
        type: String,
        required: true,
        index: true,
        set: function (val) {
            return val.trim();
        }
    },

    password: {
        type: String,
        required: false,
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
        permission: false,
        type: [
            {
                version: {
                    type: String,
                    ref: "termversion"
                },
                date: {
                    type: Date,
                    default: function () {
                        return new Date();
                    }
                }
            }
        ]
    },

    activation: {
        active: {
            permission: false,
            type: Boolean,
            default: false
        },
        token: {
            permission: false,
            type: String,
            required: false,
            default: function () {
                return crypto.randomBytes(48).toString("hex");
            }
        }
    },

    lastActivity: {
        permission: false,
        type: Date,
        default: function () {
            return new Date();
        }
    },

    _authtoken: {
        type: String,
        default: null,
        set: function (val) {
            if (!val) {
                return null;
            }

            if (typeof val === "string") {
                return val.trim() || null;
            }

            return null;
        }
    },

    reset: {
        active: {
            permission: false,
            type: Boolean,
            default: false
        },
        token: {
            permission: false,
            type: String,
            required: false
        }
    },

    permissions: {
        permission: false,
        type: [
            String
        ]
    }
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
        getters: true,
        transform: function (doc) {
            let obj = doc.toJSON({
                transform: false
            });

            delete obj.password;
            delete obj._authtoken;

            if (obj.activation) {
                delete obj.activation.token;


                if(Application.modules.auth.config.allowLoginWithoutActivation) {
                    obj.activation.active = true;
                }
            }

            if (obj.reset) {
                delete obj.reset.token;
            }

            return obj;
        }
    },
    toObject: {
        getters: true,
        virtuals: true
    },
    versionCount: 5
});

module.exports = schema;
