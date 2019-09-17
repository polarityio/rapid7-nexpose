const async = require('async');
const config = require('./config/config');
const request = require('request');
const fs = require('fs');

let Logger;
let requestWithDefaults;

function handleRequestError(request) {
  return (options, expectedStatusCode, callback) => {
    return request(options, (err, resp, body) => {
      if (err) {
        Logger.error({ error: err }, 'Error making HTTP request');
        callback({
          err: err,
          detail: 'Error making HTTP request'
        });
      } else if (resp.statusCode !== expectedStatusCode) {
        callback({
          detail: `Unexpected status code (${resp.statusCode}) when attempting HTTP request`,
          body: body,
          expectedStatusCode: expectedStatusCode,
          statusCode: resp.statusCode
        });
      } else {
        callback(null, body);
      }
    });
  };
}

function lookupIPs(entities, options, callback) {
  let requestBody = {
    filters: entities.filter((entity) => entity.isIP).map((entity) => {
      return {
        field: 'ip-address',
        operator: 'is',
        value: entity.value
      };
    }),
    match: 'any'
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
      callback(err);
      return;
    }

    let resourcesByIP = {};
    Logger.trace({ body: body }, 'Logging data');
    body.resources.forEach((resource) => {
      resourcesByIP[resource.ip] = resource;
    });

    let results = [];

    entities.forEach((entity) => {
      let resource = resourcesByIP[entity.value];
      if (!!resource) {
        resource.__isAsset = true;
        Logger.trace({ resource: resource }, 'Checking data before it gets passed');
        let critical,
          exploits,
          description,
          vulns,
          policies = 'NA';

        if (typeof resource.vulnerabilities.critical !== 'undefined') {
          critical = resource.vulnerabilities.critical;
        }
        if (typeof resource.vulnerabilities.exploits !== 'undefined') {
          exploits = resource.vulnerabilities.exploits;
        }
        if (typeof resource.osFingerprint !== 'undefined') {
          description = resource.osFingerprint.description;
        } else {
          description = 'No Operating System Provided';
        }
        if (typeof resource.assessedForVulnerabilities !== 'undefined') {
          vulns = resource.assessedForVulnerabilities;
        }
        if (typeof resource.assessedForPolicies !== 'undefined') {
          policies = resource.assessedForPolicies;
        }

        results.push({
          entity: entity,
          data: {
            summary: [
              `Critical Vulns: ${critical}`,
              `Exploits: ${exploits}`,
              `Operating System: ${description}`,
              `Assessed for Vulns: ${vulns}`,
              `Assessed for Policies: ${policies}`
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

function doLookup(entities, options, callback) {
  Logger.trace('options are', options);

  let results = [];

  async.parallel(
    [
      (done) => {
        lookupIPs(entities.filter((entity) => entity.isIP), options, (err, _results) => {
          results = results.concat(_results);
          done(err);
        });
      }
    ],
    (err) => {
      callback(err, results);
    }
  );
}

function onDetails(entity, options, callback) {
  let ro = {
    url: `${options.url}/api/3/tags`,
    qs: {
      type: 'criticality'
    },
    auth: {
      user: options.username,
      password: options.password
    },
    json: true
  };

  Logger.trace('request options are: ', ro);

  // Return all built-in tags of type "Criticality"
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

      // There are four types of tags and they appear to be built-in
      entity.data.details.appliedTags = {
        criticality: [],
        custom: [],
        location: [],
        owner: []
      };

      body.resources.forEach((tag) => {
        entity.data.details.appliedTags[tag.type].push(tag);
      });

      //body.resources;
      Logger.trace({ tagData: entity.data }, 'TagData');
      callback(null, entity.data);
    });
  });
}

function startup(logger) {
  Logger = logger;
  let requestOptions = {};

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
  if (
    typeof options[optionName].value !== 'string' ||
    (typeof options[optionName].value === 'string' && options[optionName].value.length === 0)
  ) {
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
  };

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

        let appliedTags = {
          criticality: [],
          custom: [],
          location: [],
          owner: []
        };

        tags.resources.forEach((tag) => {
          appliedTags[tag.type].push(tag);
        });

        callback(null, appliedTags);
      });
    });
  } else {
    console.error('invalid message');
    callback({
      detail: 'Invalid onMessage type received'
    });
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
