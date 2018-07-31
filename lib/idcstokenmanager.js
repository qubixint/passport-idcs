const IDCSConstants = require('./idcsconstants');
const IDCSTokenVerifier = require('./idcstokenverifier');

function IdcsTokenManager(options){
    this.options = options;
}

/**
 * This method verifies idToken given and parse ite and return IdToken Object
 * @param id_token idToken of User
 * @returns {*} decoded Id token as a JSON Object
 */
IdcsTokenManager.prototype.verifyIdToken = function (id_token) {
    var tm = this;
    return new Promise(function(resolve, reject) {
        tm.verifyToken(id_token).then(function(token){
            resolve(token);
        }).catch(function(err){
            reject(err);
        });
    });
};

/**
 * This method verifies idToken given and parse ite and return Access Token Object
 * @param access_token access_token of User
 * @returns {*} decoded Access token as a JSON Object
 */
IdcsTokenManager.prototype.verifyAccessToken = function (access_token) {
    var tm = this;
    return new Promise(function(resolve, reject) {
        tm.verifyToken(access_token).then(function(token){
            resolve(token);
        }).catch(function(err){
            reject(err);
        });
    });
};

/**
 * This method verifies token given and parse ite and return decoded token
 * @param token access_token or id_token of User
 * @returns {*} decoded token as a JSON Object
 */
IdcsTokenManager.prototype.verifyToken = function (token) {
    var options = this.options;
    var level = options[IDCSConstants.TOKEN_VALIDATION_LEVEL] ? options[IDCSConstants.TOKEN_VALIDATION_LEVEL] : IDCSConstants.VALIDATION_LEVEL_FULL;
    return new Promise(function(resolve, reject) {
        var tv = new IDCSTokenVerifier(options);
        tv.verifyJwtToken(token)
            .then(function(jwt){
                if(IDCSConstants.VALIDATION_LEVEL_FULL == level || IDCSConstants.VALIDATION_LEVEL_NORMAL == level) {
                    var type = jwt[IDCSConstants.TOKEN_CLAIM_TOKEN_TYPE];
                    var isIdToken = type=='AT' ? false : true;
                    if (!tv.validateIssuer(jwt)) {
                        reject(new Error("Failed to Validate Issuer"));
                        return;
                    }
                    if(IDCSConstants.VALIDATION_LEVEL_FULL == level || !isIdToken) {
                        tv.validateAudience(jwt, isIdToken).then(function(ret){
                            if(ret==true){
                                resolve(jwt);
                                return;
                            }else{
                                reject(new Error("Failed to Validate Audience"));
                                return;
                            }
                        }).catch(function(err){
                            reject(new Error("Failed to Validate Audience"));
                            return;
                        });
                    }
                }else {
                    resolve(jwt);
                }
            }).catch(function(err){
                reject(err);
            })

    });
};

module.exports = IdcsTokenManager;

