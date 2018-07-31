const request = require('request');
const Promise = require('promise');
const querystring = require('querystring');
const util = require('util');
const IDCSConstants = require('./idcsconstants');
const IdcsMetadataManager = require('./idcsmetadatamanager');
const IdcsAccessTokenManager = require('./idcsaccesstokenmanager');
const Jwk = require('./jwk.js');
var keys = {};

function IdcsKeyManager(options){
    this.options = options;
}

IdcsKeyManager.prototype.getPublicKey = function(){
    var options = this.options;
    return new Promise(function(resolve, reject){
        if (keys.hasOwnProperty(options[IDCSConstants.CLIENT_TENANT])) {
            var key = keys[options[IDCSConstants.CLIENT_TENANT]];
            if(key.getExpiry() > new Date().getTime()){
                resolve(key.getJwk());
                return;
            }
        }

        var mdm = new IdcsMetadataManager(options);
        mdm.getMetadata()
            .then(function(md){
                var jwkUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_JWKS_URI];
                var atm = new IdcsAccessTokenManager(options);
                atm.getAccessToken(options)
                    .then(function(at){
                        var headers = {};
                        headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BEARER, at);
                        request({
                            url: jwkUrl,
                            headers : headers
                        }, function (err, res, body) {
                            if (!err && res.statusCode == 200) {
                                var jsonObj = JSON.parse(body);
                                //this.logger.trace(`getUser, jsonObj: ${JSON.stringify(jsonObj)}`);
                                keys[options[IDCSConstants.CLIENT_TENANT]] = new Jwk(jsonObj);
                                resolve(jsonObj);
                            } else {
                                if (err) {
                                    //this.logger.error(`getUser, error: ${err}`);
                                    reject(err)
                                } else {
                                    //this.logger.error(`getUser, error: ${body}`);
                                    reject(new Error(body));
                                }
                            }
                        });
                    }).catch(function(err){
                        reject(err);
                    })
            }).catch(function(err){
                reject(err);
            })

    });
};

module.exports = IdcsKeyManager;
