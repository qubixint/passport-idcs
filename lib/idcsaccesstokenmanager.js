const request = require('request');
const Promise = require('promise');
const querystring = require('querystring');
const util = require('util');
const IdcsAuthenticationManager = require('./idcsauthenticationmanager');
const IDCSConstants = require('./idcsconstants');

var tokens = {};

function IdcsAccessTokenManager (options) {
        this.options = options;
    }

function getTokenPayload(token){
    var parts = token.split('.');
    var decoded = new Buffer(parts[1], 'base64');
    var ret = JSON.parse(decoded.toString('utf8'));
    return ret;
}

IdcsAccessTokenManager.prototype.getAccessToken = function(){
        var options = this.options;
        return new Promise(function(resolve,reject){
            if (tokens.hasOwnProperty(options[IDCSConstants.CLIENT_TENANT])) {
                var token = tokens[options[IDCSConstants.CLIENT_TENANT]];
                var payload = getTokenPayload(token);
                var now = (new Date().getTime())/1000;
                if((payload[IDCSConstants.TOKEN_CLAIM_EXPIRY] - 120) > now){
                    resolve(token);
                    return;
                }
            }

            var am = new IdcsAuthenticationManager(options);
            am.clientCredentials(IDCSConstants.MY_SCOPES)
                .then(function (res) {
                    var token = res[IDCSConstants.ACCESS_TOKEN];
                    tokens[options[IDCSConstants.CLIENT_TENANT]] = token;
                    resolve(token);
                }).catch(function (err) {
                    reject(err);
                })

        });
    };


module.exports=IdcsAccessTokenManager;