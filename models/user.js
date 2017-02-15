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

    termsAndConditions: [
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
    ],

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
            let obj = doc.toJSON({
                transform: false
            });

            delete obj.password;
            delete obj._authtoken;

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

module.exports = schema;
