"use strict";

// @IMPORTS
const Application = require("neat-base").Application;
const Promise = require("bluebird");
const mongoose = require('mongoose');
const request = require('request');

let schema = new mongoose.Schema({

    _id: {
        type: String,
        required: true
    },

    content: {
        type: String,
        required: true
    },

    url: {
        type: String,
        required: true
    }

}, {
    permissions: {
        find: true,
        findOne: true,
        count: true,
        save: false,
        remove: false
    },
    toJSON: {
        virtuals: true
    },
    toObject: {
        virtuals: true
    },
    versionsDisabled: true
});

schema.pre("validate", function (next) {

    if (this.content) {
        return next();
    }

    request(this.url, (err, res, body) => {
        if (err || res.statusCode != 200) {
            return next();
        }

        this.content = body;
        next();
    });
});

module.exports = schema;
