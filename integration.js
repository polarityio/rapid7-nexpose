let async = require('async');
let config = require('./config/config');
let request = require('request');

let Logger;
let requestWithDefaults;
let requestOptions = {};

function handleRequestError(request) {
    return (options, expectedStatusCode, callback) => {
        return request(options, (err, resp, body) => {
            if (err || resp.statusCode !== expectedStatusCode) {
                Logger.error(`error during http request to ${options.url}`, { error: err, status: resp ? resp.statusCode : 'unknown' });
                callback({ error: err, statusCode: resp ? resp.statusCode : 'unknown' });
            } else {
                callback(null, body);
            }
        });
    };
}

function lookupIPs(entities, options, callback) {
    let requestBody = {
        filters: entities
            .filter(entity => entity.isIP)
            .map(entity => {
                return {
                    field: "ip-address",
                    operator: "is",
                    value: entity.value
                };
            }),
        match: "any"
    };

    let ro = {
        url: `${options.url}/api/3/assets/search`,
        method: 'POST',
        auth: {
            user: options.username,
            password: options.password
        },
        body: requestBody,
        json: true
    };

    Logger.trace('request options are: ', ro);

    requestWithDefaults(ro, 200, (err, body) => {
        if (err) {
            Logger.error('error during lookup', err);
            callback(null, err);
            return;
        }

        let resourcesByIP = {};

        body.resources.forEach(resource => {
            resourcesByIP[resource.ip] = resource;
        });

        let results = [];

        entities.forEach(entity => {
            let resource = resourcesByIP[entity.value];
            if (!!resource) {
                resource.__isAsset = true;
                results.push({
                    entity: entity,
                    data: {
                        summary: [
                            `Critical: ${resource.vulnerabilities.critical}`,
                            `Severe: ${resource.vulnerabilities.severe}`,
                            `Exploits: ${resource.vulnerabilities.exploits}`,
                            `Services: ${resource.services.reduce((prev, next) => prev + ', ' + next.name, '')}`
                        ],
                        details: resource
                    }
                });
            } else {
                results.push({
                    entity: entity,
                    data: null
                });
            }
        });

        callback(null, results);
    });
}
/*
function pollForCompletedReport(iteration, reportUrl, options, callback) {
    Logger.trace('starting pool for completed report');

    if (iteration === 10) {
        callback({ err: new Error('polling exceeded 10 tries') });
        return;
    }

    let ro = {
        url: reportUrl,
        auth: {
            user: options.username,
            password: options.password
        }
    }

    requestWithDefaults(ro, 200, (err, body) => {
        if (err && err.statusCode !== 404) {
            Logger.error('error polling report status', { err: err });
            callback(err);
            return;
        }

        Logger.trace('report status is', body);

        if (!err && body.status === "complete") {
            callback(null, body);
            return;
        }

        Logger.trace('report is not yet ready, waiting 5 seconds');
        setTimeout(() => {
            pollForCompletedReport(iteration + 1, reportUrl, options, callback);
        }, 5 * 1000);
    });
}

function lookupCVEs(entities, options, callback) {
    let results = [];

    let ro = {
        url: `${options.url}/api/3/reports`,
        method: 'POST',
        auth: {
            user: options.username,
            password: options.password
        },
        json: true,
        body: {
            name: `polarity-${entities[0].value}-${Date.now()}`,
            owner: 1, // TODO this might need to be something different
            query: "select vul.nexpose_id from dim_vulnerability_reference ref\njoin dim_vulnerability vul\non ref.vulnerability_id = vul.vulnerability_id\nwhere ref.reference = 'CVE-2018-5996'",
            format: "sql-query",
            version: "2.3.0"
        }
    };

    Logger.trace('request options are: ', ro);

    let foundEntities = {};

    requestWithDefaults(ro, 201, (err, body) => {
        if (err) {
            Logger.error('error creating cve lookup sql query report', { err: err });
            callback({ err: err });
            return;
        }

        let selfLink = `${options.url}/api/3/reports/${body.id}`

        ro = {
            method: 'POST',
            url: selfLink + '/generate',
            auth: {
                user: options.username,
                password: options.password
            }
        };

        // Run the report
        requestWithDefaults(ro, 200, (err, body) => {
            if (err) {
                Logger.error('erroring running report', { err: err });
                callback({ err: err });
                return;
            }

            // After this point we must always delete the report before exiting
            pollForCompletedReport(0, `${selfLink}/history/${body.id}`, options, (err, body) => {
                if (err) {
                    Logger.error('error getting report', { err: err });
                    cleanupReport(options, selfLink, (err2) => {
                        if (err2) {
                            Logger.error('error cleaning up report', { err: err2 });
                            callback({ err1: err, err2: err2 });
                            return;
                        }

                        callback({ err: err });
                    });
                    return;
                }

                let dataLink = body.uri;

                ro = {
                    url: dataLink,
                    auth: {
                        user: options.username,
                        password: options.passphrase
                    }
                };

                // get the report data
                requestWithDefaults(ro, 200, (err2, body) => {
                    if (err2) {
                        cleanupReport(options, selfLink, (err2) => {
                            if (err2) {
                                Logger.error('error cleaning up report', { err: err2 });
                                callback({ err1: err, err2: err2 });
                                return;
                            }

                            callback({ err: err });
                        });
                        return;
                    }

                    cleanupReport(options, selfLink, (err) => {
                        if (err) {
                            Logger.error('error cleaning up report', { err: err1 });
                            callback({ err: err });
                            return;
                        }

                        // for each result lookup a vulnerability
                        let vulnerabilities = body.split(/\r?\n/);

                        async.each(vulnerabilities, (vulnerabilityId, cb) => {
                            let ro = {
                                uri: `${options.url}/api/3/vulnerabilities/${vulnerabilityId}`,
                                auth: {
                                    user: options.username,
                                    password: options.passphrase
                                }
                            }

                            // Lookup vulnerability
                            requestWithDefaults(ro, 200, (err, result) => {
                                if (err) {
                                    cb(err);
                                    return;
                                }

                                result.__isVulnerability = true;

                                results.push({
                                    entity: entity,
                                    data: {
                                        summary: [], // TODO add tags
                                        details: result
                                    }
                                });
                                foundEntities[entity.value] = true;
                            });
                        }, err => {
                            entities.forEach(entity => {
                                if (!foundEntities[entity.value]) {
                                    results.push({
                                        entity: entity,
                                        data: null
                                    });
                                }
                            });

                            callback(err, results);
                        });
                    });
                });
            });
        });
    });
}

function cleanupReport(options, reportLink, cb) {
    let ro = {
        url: reportLink,
        method: 'DELETE',
        auth: {
            user: options.username,
            password: options.password
        }
    };

    requestWithDefaults(ro, 200, (err) => {
        if (err) {
            Logger.error('error cleaning up report', { err: err });
            cb(err);
            return;
        }

        cb(null);
    });
}
/*
// This function validates that a CVE exists before trying to look it up
// Because the CVE standard was created in 1999, we know that any CVE with 
// a year entry of 1998 or earlier will not exist.  Likewise, a CVE with a 
// date later than the current year will also not exist (we check current year 
// + 1 to account for any date time or overlap issues).  We can safely 
// discard these results as erroneous parsing of the screen text.
function nonexistantCVE(entity) {
    let cve = entity.value;
    let year = parseInt(/CVE-(\d{4})-\d{4,7}/.exec(cve)[1]);

    return year < 1999 || year > new Date().getFullYear() + 1;
}
*/
function doLookup(entities, options, callback) {
    Logger.trace('options are', options);

    let results = [];

    async.parallel([
        (done) => {
            lookupIPs(entities.filter(entity => entity.isIP), options, (err, _results) => {
                results = results.concat(_results);
                done(err);
            });
        }/*,
        (done) => {
            lookupCVEs(entities.filter(entity => entity.types.indexOf('custom.cve') !== -1), options, (err, _results) => {
                results = results.concat(_results);
                done(err);
            });
        }*/
    ], err => {
        callback(err, results);
    });
}

function onDetails(entity, options, callback) {
    let ro = {
        url: `${options.url}/api/3/tags`,
        auth: {
            user: options.username,
            password: options.password
        },
        json: true
    };

    Logger.trace('request options are: ', ro);

    requestWithDefaults(ro, 200, (err, body) => {
        if (err) {
            callback(err);
            return;
        }

        entity.data.details.availableTags = body.resources;

        ro.url = `${options.url}/api/3/assets/${entity.data.details.id}/tags`;

        requestWithDefaults(ro, 200, (err, body) => {
            if (err) {
                callback(err);
                return;
            }

            entity.data.details.appliedTags = body.resources;

            callback(null, entity.data);
        });
    });
}

function startup(logger) {
    Logger = logger;

    if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
        requestOptions.cert = fs.readFileSync(config.request.cert);
    }

    if (typeof config.request.key === 'string' && config.request.key.length > 0) {
        requestOptions.key = fs.readFileSync(config.request.key);
    }

    if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
        requestOptions.passphrase = config.request.passphrase;
    }

    if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
        requestOptions.ca = fs.readFileSync(config.request.ca);
    }

    if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
        requestOptions.proxy = config.request.proxy;
    }

    if (typeof config.request.rejectUnauthorized === 'boolean') {
        requestOptions.rejectUnauthorized = config.request.rejectUnauthorized;
    }

    requestOptions.json = true;

    requestWithDefaults = handleRequestError(request.defaults(requestOptions));
}

function validateStringOption(errors, options, optionName, errMessage) {
    if (typeof options[optionName].value !== 'string' ||
        (typeof options[optionName].value === 'string' && options[optionName].value.length === 0)) {
        errors.push({
            key: optionName,
            message: errMessage
        });
    }
}

function onMessage(payload, options, callback) {
    Logger.trace('onMessage invoked with payload ' + JSON.stringify(payload));

    let ro = {
        json: true,
        auth: {
            user: options.username,
            password: options.password
        }
    }
    if (payload.type === 'applyTag') {
        ro.url = `${options.url}/api/3/tags/${payload.tagId}/assets/${payload.assetId}`;
        ro.method = 'PUT';

        Logger.trace('request options are: ', ro);

        requestWithDefaults(ro, 200, (err) => {
            if (err) {
                Logger.error('error applying tag ', err);
                callback(err);
                return;
            }

            ro.url = payload.tagsLink;
            ro.method = 'GET';

            requestWithDefaults(ro, 200, (err, tags) => {
                if (err) {
                    Logger.error('error fetching all tags', err);
                    callback(err);
                    return;
                }

                Logger.trace('successfully re-fetched tags');

                callback(null, tags.resources);
            });
        });
    } else if (payload.type === 'rescanSite') {
        ro.method = 'GET';
        ro.url = `${options.url}/api/3/scans/${payload.scanId}`;

        requestWithDefaults(ro, 200, (err, scan) => {
            
        });
    } else {
        console.error('invalid message');
    }
}

function validateOptions(options, callback) {
    let errors = [];

    validateStringOption(errors, options, 'url', 'You must provide a url.');
    validateStringOption(errors, options, 'username', 'You must provide a username.');
    validateStringOption(errors, options, 'password', 'You must provide a password. ');

    callback(null, errors);
}

module.exports = {
    doLookup: doLookup,
    onDetails: onDetails,
    onMessage: onMessage,
    startup: startup,
    validateOptions: validateOptions
};
