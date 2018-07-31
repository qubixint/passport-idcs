const request = require('request');
const Promise = require('promise');
const querystring = require('querystring');
var jwt = require('json-web-token');
const util = require('util');
const IdcsMetadataManager = require('./idcsmetadatamanager');
const IDCSConstants = require('./idcsconstants');

function IdcsAuthenticationManager(options) {
    this.options = options;
}

/**
 * This method returns the Authorization Code URL for the tenant for the BaseUrl present in options
 * @param redirect_uri The redirect_uri where authorization code would be sent back
 * @param scope The scopes for which the authorization code is returned
 * @param state The state to be passed to OAUTH provider
 * @param response_type The response type required from OAUTH Provider
 * @returns {Promise} when fulfilled return A complete formed URL at which the browser should hit to get the authorization code else returns error
 */
IdcsAuthenticationManager.prototype.getAuthorizationCodeUrl = function (redirect_uri, scope, state, response_type) {
    var options = this.options;
        return new Promise(function(resolve, reject) {
            if(!redirect_uri || redirect_uri==''){
                reject(new Error("Redirect Uri is Empty"));
                return;
            }
            if(!options[IDCSConstants.CLIENT_ID] || options[IDCSConstants.CLIENT_ID]==''){
                reject(new Error("Client Id is Empty"));
                return;
            }
            var mdm = new IdcsMetadataManager(options);
            mdm.getMetadata()
                .then(function (md) {
                    var params = {};
                    params[IDCSConstants.PARAM_CLIENT_ID] = options[IDCSConstants.CLIENT_ID];
                    params[IDCSConstants.PARAM_REDIRECT_URI] = redirect_uri;
                    if(response_type)
                        params[IDCSConstants.PARAM_RESPONSE_TYPE] = response_type;
                    else
                        params[IDCSConstants.PARAM_RESPONSE_TYPE] = IDCSConstants.RESPONSE_TYPE_CODE;
                    if(scope) {
                        params[IDCSConstants.PARAM_SCOPE] = scope;
                    }
                    if(state){
                        params[IDCSConstants.PARAM_STATE] = state;
                    }
                    var authzUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATION_AUTHORIZATION_ENDPOINT];
                    var query = querystring.stringify(params);
                    authzUrl+="?" + query;
                    resolve(authzUrl)
                }).catch(function (err) {
                    reject(err);
                })

        });
    };

/**
 * This methods fetched access token for the authorization code flow
 * @param code The authorization code sent by OAUTH provider
 * @returns {Promise} when fulfilled returns AuthenticationResult Object containing claims returned in Authentication else returns error
 */
IdcsAuthenticationManager.prototype.authorizationCode = function(code){
        var options = this.options;
        return new Promise(function(resolve, reject){
            if(!code || code==''){
                reject(new Error("Authorization Code is Empty"));
                return;
            }
            if(!options[IDCSConstants.CLIENT_ID] || options[IDCSConstants.CLIENT_ID]==''){
                reject(new Error("Client Id is Empty"));
                return;
            }
            if(!options[IDCSConstants.CLIENT_SECRET] || options[IDCSConstants.CLIENT_SECRET]==''){
                reject(new Error("Client Secret is Empty"));
                return;
            }
            var mdm = new IdcsMetadataManager(options);
            mdm.getMetadata()
                .then(function(md){
                    var tokenUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATION_TOKEN_ENDPOINT];
                    var params = {};
                    params[IDCSConstants.PARAM_GRANT_TYPE] = IDCSConstants.GRANT_AUTHZ_CODE;
                    params[IDCSConstants.PARAM_CODE] = code;
                    var basicAuth = new Buffer(options[IDCSConstants.CLIENT_ID] + ":" + options[IDCSConstants.CLIENT_SECRET]).toString('base64');
                    var headers = {};
                    headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.WWW_FORM_ENCODED;
                    headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BASIC, basicAuth);

                    request.post({
                        url: tokenUrl,
                        headers: headers,
                        form: params
                    }, function (err, res, body) {
                        if (!err && res.statusCode == 200) {
                            var jsonObj = JSON.parse(body);
                            resolve(jsonObj);
                        } else {
                            if (err) {
                                //this.logger.error(`authorizationCode, error: ${err}`);
                                reject(err);
                            } else {
                                //this.logger.error(`authorizationCode, error: ${body}`);
                                reject(new Error(body));
                            }
                        }
                    });
                }).catch(function(err){
                    reject(err);
                })
        });
    };

/**
 * This method fetches Access Token using resource owner OAUTH flow
 * @param username Login Id used to do login
 * @param password Password of the User
 * @param scope List of scopes for which access token is required
 * @returns {Promise} when fulfilled returns AuthenticationResult Object containing claims returned in Authentication else returns error
 */
IdcsAuthenticationManager.prototype.resourceOwner = function(username, password, scope){
        var options = this.options;
        return new Promise(function(resolve, reject){
            if(!username || username==''){
                reject(new Error("Username is Empty"));
                return;
            }
            if(!password || password==''){
                reject(new Error("Password is Empty"));
                return;
            }
            if(!options[IDCSConstants.CLIENT_ID] || options[IDCSConstants.CLIENT_ID]==''){
                reject(new Error("Client Id is Empty"));
                return;
            }
            if(!options[IDCSConstants.CLIENT_SECRET] || options[IDCSConstants.CLIENT_SECRET]==''){
                reject(new Error("Client Secret is Empty"));
                return;
            }
            var mdm = new IdcsMetadataManager(options);
            mdm.getMetadata()
                .then(function(md){
                    var tokenUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATION_TOKEN_ENDPOINT];
                    var params = {};
                    params[IDCSConstants.PARAM_GRANT_TYPE] = IDCSConstants.GRANT_PASSWORD;
                    params[IDCSConstants.PARAM_USERNAME] = username;
                    params[IDCSConstants.PARAM_PASSWORD] = password;
                    if(scope){
                        params[IDCSConstants.PARAM_SCOPE] = scope;
                    }
                    var basicAuth = new Buffer(options[IDCSConstants.CLIENT_ID] + ":" + options[IDCSConstants.CLIENT_SECRET]).toString('base64');
                    var headers = {};
                    headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.WWW_FORM_ENCODED;
                    headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BASIC, basicAuth);

                    request.post({
                        url: tokenUrl,
                        headers: headers,
                        form: params
                    }, function (err, res, body) {
                        if (!err && res.statusCode == 200) {
                            var jsonObj = JSON.parse(body);
                            resolve(jsonObj);
                        } else {
                            if (err) {
                                //this.logger.error(`resourceOwner, error: ${err}`);
                                reject(err);
                            } else {
                                //this.logger.error(`resourceOwner, error: ${body}`);
                                reject(new Error(body));
                            }
                        }
                    });
                }).catch(function(err){
                    reject(err);
                })
        });
    };

/**
 * This method fetches access token using the refresh token OAUTH flow
 * @param refresh_token The refresh token to fetch access token
 * @param scope List of scopes for which access token is required
 * @returns {Promise} when fulfilled returns AuthenticationResult Object containing claims returned in Authentication else returns error
 */
IdcsAuthenticationManager.prototype.refreshToken = function (refresh_token, scope){
        var options = this.options;
        return new Promise(function(resolve, reject){
            if(!refresh_token || refresh_token==''){
                reject(new Error("Refresh Token is Empty"));
                return;
            }
            if(!options[IDCSConstants.CLIENT_ID] || options[IDCSConstants.CLIENT_ID]==''){
                reject(new Error("Client Id is Empty"));
                return;
            }
            if(!options[IDCSConstants.CLIENT_SECRET] || options[IDCSConstants.CLIENT_SECRET]==''){
                reject(new Error("Client Secret is Empty"));
                return;
            }
            var mdm = new IdcsMetadataManager(options);
            mdm.getMetadata()
                .then(function(md){
                    var tokenUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATION_TOKEN_ENDPOINT];
                    var params = {};
                    params[IDCSConstants.PARAM_GRANT_TYPE] = IDCSConstants.GRANT_REFRESH_TOKEN;
                    params[IDCSConstants.PARAM_REFRESH_TOKEN] = refresh_token;
                    if(scope){
                        params[IDCSConstants.PARAM_SCOPE] = scope;
                    }
                    var basicAuth = new Buffer(options[IDCSConstants.CLIENT_ID] + ":" + options[IDCSConstants.CLIENT_SECRET]).toString('base64');
                    var headers = {};
                    headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.WWW_FORM_ENCODED;
                    headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BASIC, basicAuth);

                    request.post({
                        url: tokenUrl,
                        headers: headers,
                        form: params
                    }, function (err, res, body) {
                        if (!err && res.statusCode == 200) {
                            var jsonObj = JSON.parse(body);
                            resolve(jsonObj);
                        } else {
                            if (err) {
                                //this.logger.error(`refreshToken, error: ${err}`);
                                reject(err);
                            } else {
                                //this.logger.error(`refreshToken, error: ${body}`);
                                reject(new Error(body));
                            }
                        }
                    });
                }).catch(function(err){
                    reject(err);
                })
        });
    };

/**
 * This method fetches Access Token using the Client Credentials OAUTH Flow
 * @param client_id The client Id of Application
 * @param client_secret The client secret of Application
 * @param scope List of scopes for which access token is required
 * @returns {Promise} when fulfilled returns AuthenticationResult Object containing claims returned in Authentication else returns error
 */
IdcsAuthenticationManager.prototype.clientCredentials = function (scope){
        var options = this.options;
        return new Promise(function(resolve, reject){
            if(!options[IDCSConstants.CLIENT_ID] || options[IDCSConstants.CLIENT_ID]==''){
                reject(new Error("Client Id is Empty"));
                return;
            }
            if(!options[IDCSConstants.CLIENT_SECRET] || options[IDCSConstants.CLIENT_SECRET]==''){
                reject(new Error("Client Secret is Empty"));
                return;
            }
            var mdm = new IdcsMetadataManager(options);
            mdm.getMetadata()
                .then(function(md){
                    var tokenUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATION_TOKEN_ENDPOINT];

                    var params = {};
                    params[IDCSConstants.PARAM_GRANT_TYPE] = IDCSConstants.GRANT_CLIENT_CRED;
                    params[IDCSConstants.PARAM_SCOPE] = scope;

                    var basicAuth = new Buffer(options[IDCSConstants.CLIENT_ID] + ":" + options[IDCSConstants.CLIENT_SECRET]).toString('base64');
                    var headers = {};
                    headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.WWW_FORM_ENCODED;
                    headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BASIC, basicAuth);

                    request.post({
                        url: tokenUrl,
                        headers: headers,
                        form: params
                    }, function (err, res, body) {
                        if (!err && res.statusCode == 200) {
                            var jsonObj = JSON.parse(body);
                            resolve(jsonObj)
                        } else {
                            if (err) {
                                //this.logger.error(`clientCredentials, error: ${err}`);
                                reject(err);
                            } else {
                                //this.logger.error(`clientCredentials, error: ${body}`);
                                reject(new Error(body));
                            }
                        }
                    });

                }).catch(function(err){
                    reject(err);
                })
        });
    };

/**
 * This method fetches access token using the Client Assertion OAUTH flow
 * @param user_assertion User Assertion as JSON WEB Token
 * @param client_assertion Client Assertion as JSON WEB Token
 * @param scope List of scopes for which access token is required
 * @returns {Promise} when fulfilled returns AuthenticationResult Object containing claims returned in Authentication else returns error
 */
IdcsAuthenticationManager.prototype.clientAssertion = function (user_assertion, client_assertion, scope){
        var options = this.options;
        return new Promise(function(resolve, reject){
            if(!client_assertion || client_assertion==''){
                reject(new Error("Client Assertion is Empty"));
                return;
            }
            if(!user_assertion || user_assertion==''){
                reject(new Error("User Assertion is Empty"));
                return;
            }
            var mdm = new IdcsMetadataManager(options);
            mdm.getMetadata()
                .then(function(md){
                    var tokenUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATION_TOKEN_ENDPOINT];
                    var params = {};
                    params[IDCSConstants.PARAM_GRANT_TYPE] = IDCSConstants.GRANT_ASSERTION;
                    params[IDCSConstants.PARAM_ASSERTION] = user_assertion;
                    params[IDCSConstants.PARAM_CLIENT_ID] = options[IDCSConstants.CLIENT_ID];
                    params[IDCSConstants.PARAM_CLIENT_ASSERTION] = client_assertion;
                    params[IDCSConstants.PARAM_CLIENT_ASSERTION_TYPE] = IDCSConstants.ASSERTION_TYPE_JWT;
                    if(scope){
                        params[IDCSConstants.PARAM_SCOPE] = scope;
                    }
                    var headers = {};
                    headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.WWW_FORM_ENCODED;

                    request.post({
                        url: tokenUrl,
                        headers: headers,
                        form: params
                    }, function (err, res, body) {
                        if (!err && res.statusCode == 200) {
                            var jsonObj = JSON.parse(body);
                            resolve(jsonObj);
                        } else {
                            if (err) {
                                //this.logger.error(`clientAssertion, error: ${err}`);
                                reject(err);
                            } else {
                                //this.logger.error(`clientAssertion, error: ${body}`);
                                reject(new Error(body));
                            }
                        }
                    });
                }).catch(function(err){
                    reject(err);
                })
        });
    };

/**
 * This method fetches access token using the User Assertion OAUTH flow
 * @param user_assertion User Assertion as JSON WEB Token
 * @param scope List of scopes for which access token is required
 * @returns {Promise} when fulfilled returns AuthenticationResult Object containing claims returned in Authentication else returns error
 */
IdcsAuthenticationManager.prototype.userAssertion = function (user_assertion, scope){
        var options = this.options;
        return new Promise(function(resolve, reject){
            if(!user_assertion || user_assertion==''){
                reject(new Error("User Assertion is Empty"));
                return;
            }
            if(!options[IDCSConstants.CLIENT_ID] || options[IDCSConstants.CLIENT_ID]==''){
                reject(new Error("Client Id is Empty"));
                return;
            }
            if(!options[IDCSConstants.CLIENT_SECRET] || options[IDCSConstants.CLIENT_SECRET]==''){
                reject(new Error("Client Secret is Empty"));
                return;
            }
            var mdm = new IdcsMetadataManager(options);
            mdm.getMetadata()
                .then(function(md){
                    var tokenUrl = md[IDCSConstants.META_OPENID_CONFIGURATION][IDCSConstants.META_OPENID_CONFIGURATION_TOKEN_ENDPOINT];
                    var params = {};
                    params[IDCSConstants.PARAM_GRANT_TYPE] = IDCSConstants.GRANT_ASSERTION;
                    params[IDCSConstants.PARAM_ASSERTION] = user_assertion;
                    if(scope){
                        params[IDCSConstants.PARAM_SCOPE] = scope;
                    }
                    var basicAuth = new Buffer(options[IDCSConstants.CLIENT_ID] + ":" + options[IDCSConstants.CLIENT_SECRET]).toString('base64');
                    var headers = {};
                    headers[IDCSConstants.HEADER_CONTENT_TYPE] = IDCSConstants.WWW_FORM_ENCODED;
                    headers[IDCSConstants.HEADER_AUTHORIZATION] = util.format(IDCSConstants.AUTH_BASIC, basicAuth);

                    request.post({
                        url: tokenUrl,
                        headers: headers,
                        form: params
                    }, function (err, res, body) {
                        if (!err && res.statusCode == 200) {
                            var jsonObj = JSON.parse(body);
                            resolve(jsonObj);
                        } else {
                            if (err) {
                                //this.logger.error(`userAssertion, error: ${err}`);
                                reject(err);
                            } else {
                                //this.logger.error(`userAssertion, error: ${body}`);
                                reject(new Error(body));
                            }
                        }
                    });
                }).catch(function(err){
                    reject(err);
                })
        });
    };

/**
 * This method produces a signed JWT from the given claims
 * @param privateKey RSA Private Key to sign the assertion
 * @param headers A map of headers for Signed token. Claims kid or x5t are mandatory
 * @param claims A map of claims for Signed token. Claims sub,exp,aud are mandatory
 * @param alg The algorithm used to sign. Default is RS256
 * @returns {Promise} Serialized Signed Json Web Token else returns error
 */
IdcsAuthenticationManager.prototype.generateAssertion = function(privateKey, headers, claims, alg){
    return new Promise(function(resolve, reject) {
        if(!claims[IDCSConstants.TOKEN_CLAIM_SUBJECT]){
            reject(new Error("Subject claim is missing"));
            return;
        }
        if(!claims[IDCSConstants.TOKEN_CLAIM_AUDIENCE]){
            reject(new Error("Audience claim is missing"));
            return;
        }
        if(!claims[IDCSConstants.TOKEN_CLAIM_EXPIRY]){
            reject(new Error("Expiry claim is missing"));
            return;
        }
        if(!claims[IDCSConstants.TOKEN_CLAIM_ISSUE_AT]){
            reject(new Error("Issue At claim is missing"));
            return;
        }
        if(!claims[IDCSConstants.TOKEN_CLAIM_ISSUER]){
            reject(new Error("Issuer claim is missing"));
            return;
        }

        if(!headers[IDCSConstants.HEADER_CLAIM_KEY_ID]){
            if(!headers[IDCSConstants.HEADER_CLAIM_X5_THUMB]){
                reject(new Error("No kid or x5t present in header"));
                return;
            }
        }

        if (!alg) {
            alg = 'RS256';
        }
        headers.alg = alg;
        headers.typ = "JWT";

        var body = {};
        body.payload = claims;
        body.header = headers;

        try {
            jwt.encode(privateKey, body, alg, function(err,token){
                if(err){
                    reject(err);
                }else {
                    resolve(token);
                }
            });
        }catch(err){
            reject(err);
        }
    });
};

module.exports = IdcsAuthenticationManager;