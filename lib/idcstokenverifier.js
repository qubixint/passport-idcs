const jwkToPem = require('jwk-to-pem');
const jwt = require('jsonwebtoken');
const Promise = require('promise');
const url = require('url');
const querystring = require('querystring');
const util = require('util');
const IDCSConstants = require('./idcsconstants');
const IdcsKeyManager = require('./idcskeymanager');
const IdcsAccessTokenManager = require('./idcsaccesstokenmanager');
const LRU = require('lru');
const request = require('request');

var evicted;
var scopeCache = null;

function IdcsTokenVerifier (options) {
    this.options = options;
    if (scopeCache == null) {
        var opts = {};
        if (options[IDCSConstants.USER_CACHE_MAX_SIZE]) {
            opts["max"] = options[IDCSConstants.USER_CACHE_MAX_SIZE];
        } else {
            opts["max"] = IDCSConstants.USER_CACHE_MAX_SIZE_DEFAULT;
        }

        if (options[IDCSConstants.FQS_RESOURCE_CACHE_TTL]) {
            opts["maxAge"] = options[IDCSConstants.FQS_RESOURCE_CACHE_TTL] * 1000;
        } else {
            opts["maxAge"] = IDCSConstants.FQS_RESOURCE_CACHE_TTL_DEFAULT * 1000;
        }

        scopeCache = new LRU(opts);
        scopeCache.on('evict', function (data) {
            evicted = data
        });

    }
}

/**
 * TODO use following logic for issuer validation
 *  claims to verify
 let verifyClaims = {
      clockTolerance: this.verifyClaims.clockTolerance,
      issuer: this.verifyClaims.issuer ? this.verifyClaims.issuer : data.issuer,
        algorithms: [publicKey.alg]}
 };
 */

IdcsTokenVerifier.prototype.verifyJwtToken = function(token) {
    var options = this.options;
    var level = options[IDCSConstants.TOKEN_VALIDATION_LEVEL] ? options[IDCSConstants.TOKEN_VALIDATION_LEVEL] : IDCSConstants.VALIDATION_LEVEL_FULL;
    return new Promise(function(resolve, reject){
        var km = new IdcsKeyManager(options);
        km.getPublicKey()
            .then(function(jwk){
                var tokenDecoded = jwt.decode(token, {
                    complete: true
                });
                if (!tokenDecoded) {
                    var err = 'failed to decode Token';
                    reject(new Error(err));
                }
                // get kid used to sign the token
                var kid = tokenDecoded.header.kid;
                var keys = jwk.keys;
                var key;
                if (kid) {
                    key = keys.find((n) => n.kid = kid);
                }

                if(!key){
                    key = keys[0];
                }

                var pem = jwkToPem(key);
                var result;
                try{
                    if(IDCSConstants.VALIDATION_LEVEL_NONE == level){
                        result = tokenDecoded;
                    }else {
                        var skew = IDCSConstants.TOKEN_CLOCK_SKEW_DEFAULT_VALUE;
                        if (options[IDCSConstants.TOKEN_CLOCK_SKEW]) {
                            skew = options[IDCSConstants.TOKEN_CLOCK_SKEW];
                        }
                        result = jwt.verify(token, pem, {clockTolerance: skew, algorithms: [key.alg]});
                        var d = new Date();
                        if ((result[IDCSConstants.TOKEN_CLAIM_EXPIRY] + skew) <= d.getTime() / 1000) {
                            reject(new Error("Token is Expired"));
                        }
                    }
                    resolve(result);
                }catch(err){
                    reject(err);
                }
            }).catch(function(err){
                reject(err);
            })
    });
};

IdcsTokenVerifier.prototype.validateAudience = function(token, isIdToken){
    var options = this.options;
    var tv = this;
    return new Promise(function(resolve, reject){
        if(!token.hasOwnProperty(IDCSConstants.TOKEN_CLAIM_AUDIENCE)){
            if(!token.hasOwnProperty(IDCSConstants.TOKEN_CLAIM_SCOPE)){
                resolve(false);
            }else{
                if(token[IDCSConstants.TOKEN_CLAIM_SCOPE].trim()==''){
                    resolve(false);
                }else{
                    resolve(true);
                }
            }
        }else{
            var aud = token[IDCSConstants.TOKEN_CLAIM_AUDIENCE];
            if(!(aud instanceof Array)){
                aud = [aud];
            }
            var necessary = tv.getNecessaryAudience(aud);
            if(necessary.length>0){
                tv.validateNecessaryAudience(token, necessary).then(function(ret){
                    resolve(ret);
                }).catch(function(err){
                    reject(err);
                });
            }else{
                tv.validateSufficientAudience(aud, isIdToken).then(function(ret){
                    resolve(ret);
                }).catch(function(err){
                    reject(err);
                });
            }
        }
    });
};

IdcsTokenVerifier.prototype.getNecessaryAudience = function(aud){
    var necessary  = [];
    for(var i=0; i<aud.length; i++){
        var audience = aud[i];
        if(audience.startsWith(IDCSConstants.NECESSARY_AUDIENCE_PREFIX)){
            necessary.push(audience);
        }
    }
    return necessary;
}

IdcsTokenVerifier.prototype.validateNecessaryAudience = function(token, necessary){
    var tv = this;
    return new Promise(function(resolve, reject){
        var validations = [];
        for(var i=0; i<necessary.length; i++){
            var audience = necessary[i];
            validations.push(tv.__validateNecessaryAudience(token, audience));
        }
        Promise.all(validations).then(function(values){
            for(var j=0; j<values.length; j++){
                var value = values[j];
                if(value==false){
                    resolve(false);
                    return;
                }
            }
            resolve(true);
        }).catch(function(err){
            reject(err);
        });
    });
}

IdcsTokenVerifier.prototype.__validateNecessaryAudience = function(token, audience){
    var tv = this;
    return new Promise(function(resolve, reject){
        if(audience==IDCSConstants.AUDIENCE_SCOPE_ACCOUNT){
            tv.__validateScopeAccount(token).then(function(ret){
                resolve(ret);
            }).catch(function(err){
                reject(err);
            })
        }else if(audience.startsWith(IDCSConstants.AUDIENCE_SCOPE_TAG)){
            tv.__validateScopeTag(audience).then(function(ret){
                resolve(ret);
            }).catch(function(err){
                reject(err);
            });
        }else{
            resolve(false);
        }
    });
}

IdcsTokenVerifier.prototype.__validateScopeAccount = function(token){
    var options = this.options;
    return new Promise(function(resolve, reject){
        var client_tenant = token[IDCSConstants.TOKEN_CLAIM_TENANT];
        if(client_tenant==options[IDCSConstants.CLIENT_TENANT]){
            resolve(true);
        }else{
            resolve(false);
        }
    });
}

IdcsTokenVerifier.prototype.__validateScopeTag = function(audience){
    var tv = this;
    var options = this.options;
    return new Promise(function(resolve, reject){
        tv.getTokenTags(audience).then(function(tokenTags){
            if(options[IDCSConstants.FULLY_QUALIFIED_SCOPES]){
                var scopes = options[IDCSConstants.FULLY_QUALIFIED_SCOPES].split(",");
                var tags = [];
                for(var i=0; i<scopes.length; i++) {
                    var scope = scopes[i];
                    tags.push(tv.getTagsForResource(scope));
                }
                Promise.all(tags).then(function(values){
                    for(var j=0; j<values.length; j++){
                        var resourceTags = values[j];
                        for (var tag in resourceTags){
                            if(tokenTags.hasOwnProperty(tag)) {
                                resolve(true);
                                return;
                            }
                        }
                    }
                    resolve(false);
                });
            }else{
                reject(new Error("FullyQualifiedScopes missing in Options"))
            }
        }).catch(function(err){
            reject(err);
        })
    });
}

IdcsTokenVerifier.prototype.getTokenTags = function(audience){
    return new Promise(function(resolve, reject){
        var tokenTags = {};
        var i = audience.indexOf("=");
        var decoded = Buffer.from(audience.substring(i+1), 'base64').toString("ascii");
        var parsed = JSON.parse(decoded);
        if(parsed["tags"]){
            var tags = parsed["tags"];
            for(var j=0; j<tags.length; j++){
                var tag = tags[j];
                tokenTags[tag["key"] + ":" + tag["value"]] = "";
            }
        }
        resolve(tokenTags);
    });

}

IdcsTokenVerifier.prototype.getTagsForResource = function(scope){
    var key = scope;
    var options = this.options;
    var resourceTags = {};
    return new Promise(function(resolve, reject){
        var ret = scopeCache.get(key);
        if(ret){
            resolve(ret);
            return;
        }
        var atm = new IdcsAccessTokenManager(options);
        atm.getAccessToken().then(function(at){
            var url = getBaseUrl(options);
            url+=IDCSConstants.GET_APP_INFO_PATH;
            url+=util.format(IDCSConstants.FQS_FILTER, "\"" + scope + "\"");

            var headers = {};
            headers[IDCSConstants.HEADER_AUTHORIZATION] =  util.format(IDCSConstants.AUTH_BEARER, at);
            request({
                url: url,
                headers : headers
            }, function (err, res, body) {
                if (!err && res.statusCode == 200) {
                    var jsonObj = JSON.parse(body);
                    var resources = jsonObj["Resources"];
                    for(var i=0; i<resources.length; i++){
                        var resource = resources[i];
                        if(resource["tags"]){
                            var tags = resource["tags"];
                            for(var j=0; j<tags.length; j++){
                                var tag = tags[j];
                                var resKey = tag["key"] + ":" + tag["value"];
                                resourceTags[resKey] = "";
                            }
                        }
                    }
                    //this.logger.trace(`getUser, jsonObj: ${JSON.stringify(jsonObj)}`);
                    scopeCache.set(key, resourceTags);
                    resolve(resourceTags);
                } else {
                    if (err) {
                        //this.logger.error(`getUser, error: ${err}`);
                        reject(err);
                    } else {
                        //this.logger.error(`getUser, error: ${body}`);
                        reject(new Error(body));
                    }
                }
            });

        }).catch(function(err){
            reject(err);
        });
    });
}

IdcsTokenVerifier.prototype.validateSufficientAudience = function(aud, idToken){
    var options = this.options;
    var tv = this;
    return new Promise(function(resolve, reject){
        var i;
        for(i=0; i<aud.length; i++){
            var audience = aud[i];
            if(idToken){
                if(audience == options[IDCSConstants.CLIENT_ID]){
                    resolve(true);
                }
            }else{
                if(tv.__validateSufficientAudience(url.parse(audience), url.parse(options[IDCSConstants.AUDIENCE_SERVICE_URL]), options[IDCSConstants.RESOURCE_TENANCY], options[IDCSConstants.CROSS_TENANT])){
                    resolve(true);
                }
            }
        }
        resolve(false);
    });
}

IdcsTokenVerifier.prototype.__validateSufficientAudience = function(audienceUrl, serviceUrl, resourceTenancy, crossTenant){
    if(audienceUrl.protocol != serviceUrl.protocol){
        return false;
    }

    var host = audienceUrl.hostname;
    if(crossTenant){
        var idx = host.indexOf('.');
        host = resourceTenancy + host.substr(idx);
    }

    if(host != serviceUrl.hostname){
        return false;
    }

    var audPort, servicePort;


    if(audienceUrl.port === null){
        if(audienceUrl.protocol === 'https:'){
            audPort = '443';
        }else{
            audPort = '80';
        }
    } else {
        audPort = audienceUrl.port;
    }

    if(serviceUrl.port === null){
        if(serviceUrl.protocol === 'https:'){
            servicePort = '443';
        }else{
            servicePort = '80';
        }
    } else {
        servicePort = serviceUrl.port;
    }

    if(audPort !== servicePort){
        return false;
    }

    if(audienceUrl.pathname){
        if(!serviceUrl.pathname.startsWith(audienceUrl.pathname))
            return false;
    }
    return true;

};

IdcsTokenVerifier.prototype.validateIssuer = function(token){
    var issuerUrl = url.parse(this.options[IDCSConstants.TOKEN_ISSUER]);
    var issUrl = url.parse(token[IDCSConstants.TOKEN_CLAIM_ISSUER]);

    if(issuerUrl.protocol != issUrl.protocol){
        return false;
    }

    if(issuerUrl.hostname != issUrl.hostname){
        return false;
    }

    if(issuerUrl.port != issUrl.port){
        return false;
    }
    return true;
};

function getBaseUrl(options){
    var url = options[IDCSConstants.IDCSHost];
    url = url.replace('%tenant%', options[IDCSConstants.CLIENT_TENANT]);
    return url;
}


module.exports = IdcsTokenVerifier;
