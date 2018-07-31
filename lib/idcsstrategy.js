'use strict';

const passport = require('passport');

const Logger = require('./logger');
const CONSTANTS = require('./constants');
const IdcsConstants = require('./idcsconstants');
const AuthenticationManager = require('./idcsauthenticationmanager');
const TokenManager = require('./idcstokenmanager');

class IdcsStrategy extends passport.Strategy {
    constructor(options, verify) {
        super();

        // verify configurations
        this.options = CONSTANTS.validateOptions(options);
        this.name = 'Idcs';
        this.verify = verify;

        Logger.setLevel(this.options[CONSTANTS.LOG_LEVEL]);
        this.logger = Logger.getLogger('IdcsStrategy');
        this.logger.trace(`constructor, options: ${options}, options after handling: ${this.options}`);

    }

    /**
     * Authenticate request.
     *
     * @param {Object} req The request to authenticate.
     * @param {Object} options Strategy-specific options.
     * @api public
     */
    authenticate(req, options) {
        this.logger.trace(`authenticate, headers: ${JSON.stringify(req.headers)}, options: ${options}`);

        let oidc = this;
        let opts = this.options;
        let am = new AuthenticationManager(opts);
        let tm = new TokenManager(opts);
        if(req.query.code){
            let code = req.query.code;
            let state = req.query.state;
            am.authorizationCode(code)
                .then(function(result){
                    var info = {};
                    info.state = state;
                    info.access_token = result.access_token;
                    info.id_token = result.id_token;
                    info.refresh_token = result.refresh_token;
                    tm.verifyAccessToken(result.access_token)
                        .then(function(token){
                            let complete = function(usr,err){
                                if(err){
                                    oidc.fail(err);
                                }else{
                                    oidc.success(usr,info);
                                }
                            };

                            oidc.verify(req, info, complete);
                        }).catch(function(err){
                            oidc.fail(err);
                        });
                }).catch(function(err){
                    oidc.fail(err);
                });
        }else{
            let redirect_uri = options[IdcsConstants.PARAM_REDIRECT_URI];
            let scope = options[IdcsConstants.PARAM_SCOPE];
            let state = options[IdcsConstants.PARAM_STATE];
            let response_type = options[IdcsConstants.PARAM_RESPONSE_TYPE];
            if(!redirect_uri){
                oidc.fail(new Error('CallBackURL missing in options'));
                return;
            }
            if(!scope){
                scope = "openid";
            }
            if(!state){
                state = "";
            }
            if(!response_type){
                response_type = IdcsConstants.RESPONSE_TYPE_CODE;
            }

            am.getAuthorizationCodeUrl(redirect_uri, scope, state, response_type)
                .then(function(url){
                    oidc.redirect(url);
                }).catch(function(err){
                    oidc.fail(err);
                });
        }

    }
}

module.exports = IdcsStrategy;
