const request = require('request');
const Promise = require('promise');
const querystring = require('querystring');
const util = require('util');
const IDCSConstants = require('./idcsconstants');
const Metadata = require('./metadata.js');
var metadata = {};

function IdcsMetadataManager (options){
    this.options = options;
}

IdcsMetadataManager.prototype.getMetadata = function() {
    var options = this.options;
    return new Promise(function (resolve, reject) {
        if (metadata.hasOwnProperty(options[IDCSConstants.CLIENT_TENANT])) {
            var md = metadata[options[IDCSConstants.CLIENT_TENANT]];
            if(md.getExpiry() > new Date().getTime()) {
                resolve(md.getMetadata());
                return;
            }
        }

        var url = getBaseUrl(options);

        request({
            url: url
        }, function (err, res, body)  {
            if (!err && res.statusCode == 200) {
                var jsonObj = JSON.parse(body);
                //this.logger.trace(`getMetadata, jsonObj: ${JSON.stringify(jsonObj)}`);
                metadata[options[IDCSConstants.CLIENT_TENANT]] = new Metadata(jsonObj);
                resolve(jsonObj);
            } else {
                if (err) {
                    //this.logger.error(`getMetadata, error: ${err}`);
                    reject(err);
                } else {
                    //this.logger.error(`getMetadata, error: ${body}`);
                    reject(new Error(body));
                }
            }
        });
    });
}

function getBaseUrl(options){
    var url = options[IDCSConstants.IDCSHost] + IDCSConstants.DISCOVERY_PATH;
    url = url.replace('%tenant%', options[IDCSConstants.CLIENT_TENANT]);
    return url;
}

module.exports = IdcsMetadataManager;
