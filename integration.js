const async = require('async');
const config = require('./config/config');
const request = require('postman-request');
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

function getSummaryTags(resources, isCve) {
  const tags = [];
  if (!Array.isArray(resources)) {
    resources = [resources];
  }

  if (resources.length > 1) {
    return [`${resources.length} assets`];
  } else if (resources.length === 1) {
    let resource = resources[0];

    if(resource.ip && isCve){
      tags.push(resource.ip);
    }

    if (typeof resource.osFingerprint !== 'undefined') {
      tags.push(`OS: ${resource.osFingerprint.description}`);
    }

    if (typeof resource.vulnerabilities.critical !== 'undefined') {
      tags.push(`Critical Vulns: ${resource.vulnerabilities.critical}`);
    }

    if (typeof resource.vulnerabilities.exploits !== 'undefined') {
      tags.push(`Exploits: ${resource.vulnerabilities.exploits}`);
    }

    return tags;
  } else {
    return ['No Results'];
  }
}

function lookupCves(entities, options, callback) {
  const cveResults = [];
  async.each(
    entities,
    (entity, done) => {
      const requestOptions = {
        url: `${options.url}/api/3/assets/search`,
        method: 'POST',
        auth: {
          user: options.username,
          password: options.password
        },
        body: {
          filters: [
            {
              field: 'cve',
              operator: 'is',
              value: entity.value
            }
          ],
          match: 'any'
        },
        json: true
      };

      Logger.trace({ requestOptions }, 'CVE Search Request Options');

      requestWithDefaults(requestOptions, 200, (err, body) => {
        if (err) {
          Logger.error({ body });
          done(err);
          return;
        }

        if (body.resources.length > 0) {
          cveResults.push({
            entity: entity,
            data: {
              summary: getSummaryTags(body.resources, true),
              details: {
                resources: body.resources
              }
            }
          });
        } else {
          cveResults.push({
            entity: entity,
            data: null
          });
        }

        done();
      });
    },
    (err) => {
      callback(err, cveResults);
    }
  );
}

function lookupIPs(entities, options, callback) {
  let requestBody = {
    filters: entities.map((entity) => {
      return {
        field: entity.type === 'cve' ? 'cve' : 'ip-address',
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

  Logger.trace({ requestOptions: ro }, 'IP Search Request Options');

  requestWithDefaults(ro, 200, (err, body) => {
    if (err) {
      callback(err);
      return;
    }

    let resourcesByIP = {};

    body.resources.forEach((resource) => {
      resourcesByIP[resource.ip] = resource;
    });

    let results = [];

    entities.forEach((entity) => {
      let resource = resourcesByIP[entity.value];
      if (!!resource) {
        resource.__isAsset = true;
        Logger.trace(
          { resource: resource, entity: entity.value },
          'Checking data before it gets passed'
        );

        results.push({
          entity: entity,
          data: {
            summary: getSummaryTags(resource),
            details: {
              resources: [resource]
            }
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
  Logger.trace({ entities }, 'doLookup');

  let lookupResults = [];

  const ipAddresses = entities.filter((entity) => entity.isIP);
  const cves = entities.filter((entity) => entity.types.indexOf('cve') >= 0);

  async.parallel(
    {
      ipLookups: function (done) {
        if (ipAddresses.length > 0) {
          lookupIPs(ipAddresses, options, (err, _results) => {
            lookupResults = lookupResults.concat(_results);
            done(err);
          });
        } else {
          done();
        }
      },
      cveLookups: function (done) {
        if (cves.length > 0) {
          lookupCves(cves, options, (err, _results) => {
            lookupResults = lookupResults.concat(_results);
            done(err);
          });
        } else {
          done();
        }
      }
    },
    (err) => {
      Logger.trace({ lookupResults }, 'Lookup Results');
      callback(err, lookupResults);
    }
  );
}

function onDetails(resultObject, options, callback) {
  let requestOptions = {
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

  Logger.trace({ requestOptions }, 'Request Options');

  // Return all built-in tags of type "Criticality"
  requestWithDefaults(requestOptions, 200, (err, body) => {
    if (err) {
      callback(err);
      return;
    }

    resultObject.data.details.availableTags = body.resources;

    async.each(
      resultObject.data.details.resources,
      (resource, done) => {
        requestOptions.url = `${options.url}/api/3/assets/${resource.id}/tags`;

        requestWithDefaults(requestOptions, 200, (err, body) => {
          if (err) {
            done(err);
            return;
          }

          Logger.trace({body}, 'onDetails Response Body');

          // There are four types of tags and they appear to be built-in
          resource.appliedTags = {
            criticality: [],
            custom: [],
            location: [],
            owner: []
          };

          body.resources.forEach((tag) => {
            resource.appliedTags[tag.type].push(tag);
          });

          done(null);
        });
      },
      (err) => {
        callback(null, resultObject.data);
      }
    );
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
