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

    content: [
        {
            type: String,
            required: true
        }
    ],

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
    let urls = this.url.split(",");

    if (this.content && typeof this.content !== "string" && this.content.length === urls.length) { // check for string for legacy reasons
        return next();
    }

    let contents = [];
    Promise.map(urls, (url) => {
        return new Promise((resolve, reject) => {
            request(url, (err, res, body) => {
                if (err || res.statusCode != 200) {
                    return resolve();
                }

                contents.push(body);
                resolve();
            });
        });
    }).then(() => {
        this.content = contents;
        next();
    }, () => {
        next();
    });
});

module.exports = schema;
