/*
DESCRIPTION
IDCS server's passport authentication strategy.

MODIFIED    (MM/DD/YY)
xinnwang    12/06/16 - Refacotoring
junyhe      11/18/16 - Creation
 */
'use strict';

// core module
const passport = require('passport');

// project module
const Logger = require('./logger');
const CONSTANTS = require('./constants');
const UserManager = require('./idcsusermanager');
// id token header name
const ID_TOKEN_HEADER_KEY = 'idcs_user_assertion';
const USER_ID_HEADER_KEY = "idcs_user_id";
// user tenant header name
const TENANT_HEADER_KEY = 'x-user-identity-domain-name';

class OIDCStrategy extends passport.Strategy {
	/**
	 * Constructor for OIDCStrategy
	 *  @constructor
	 *  @param {Object}       options Configurations for idcs oidc strategy.
	 * - JwksUri              Optional, Public key file path which will be used to verify the id token, if it is not assigned, public key will be retrieved from IDCS server.
	 * - IDCSHost             Required, IDCS host address. e.g. https://%tenant%.idcspool0.identity.c9dev0.oraclecorp.com
	 * - ClientTenant         Required, OAuth client tenant
	 * - ClientId             Required, OAuth client id
	 * - ClientSecret         Required, OAuth client secret
	 * - TokenClockSkew     Optional, number of seconds to tolerate when checking the nbf and exp claims, to deal with small clock differences among different servers, default: 300
	 * - MetaDataCacheMaxSize Optional, number of cached size for meta data and key file, default: 1000
	 * - MetaDataCacheTTL     Optional, number of seconds for cached item, default: 86400(24h)
	 * - LogLevel             Optional, set logging level, default level: warn
	 * @param {Function} verify
	 * @access public
	 */
	constructor(options, verify) {
		super();

		// verify configurations
		this.options = CONSTANTS.validateOptions(options);
		this.name = 'IDCSOIDC';
		this.verify = verify;

		Logger.setLevel(this.options[CONSTANTS.LOG_LEVEL]);
		this.logger = Logger.getLogger('OIDCStrategy');
		this.logger.trace(`constructor, options: ${options}, options after handling: ${this.options}`);

		let verifyClaims = {
			clockTolerance: this.options[CONSTANTS.TOKEN_CLOCK_SKEW]
		};
		if (this.options[CONSTANTS.TOKEN_CLAIM_ISSUER]) {
			verifyClaims.issuer = this.options[CONSTANTS.TOKEN_CLAIM_ISSUER];
		}

		let oauthClientOptions = {
			clientId: this.options[CONSTANTS.CLIENT_ID],
			clientSecret: this.options[CONSTANTS.CLIENT_SECRET],
			tokenTimeoutWindow: this.options[CONSTANTS.TOKEN_TIMEOUT_WINDOW],
			clientTenant: this.options[CONSTANTS.CLIENT_TENANT]
		};

		this.metadataUrl = `${this.options[CONSTANTS.IDCSHost]}${CONSTANTS.DISCOVERY_PATH}`;
	}

	getMetadataUrl(tenant) {
		return this.metadataUrl.replace('%tenant%', tenant);
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

		let idToken = req.headers[ID_TOKEN_HEADER_KEY];
		let userId = req.headers[USER_ID_HEADER_KEY];
		let oidc = this;
		let opts = this.options;
		let tenant = this.options[CONSTANTS.CLIENT_TENANT];
		let complete = function(err, user){
			if(err){
				oidc.fail(err);
			}else{
				oidc.success(user)
			}
		};
		if(userId){
			let um = new UserManager(opts);
			um.getUser(userId)
				.then(function(idcsUser){
					let user = CONSTANTS.populateUserFromIdcsUserObject(idcsUser, tenant);
					oidc.verify(userId, tenant, user, complete);
				}).catch(function(err){
					oidc.fail(err);
				});
		}else if(idToken){
			let um = new UserManager(opts);
			um.assertClaims(idToken).then(function(res){
				oidc.verify(res.token, res.token.user_tenantname, res.result, complete);
			}).catch(function(err){
				oidc.fail(err);
			});
		}else{
			return this.fail(`missing ${ID_TOKEN_HEADER_KEY} and ${USER_ID_HEADER_KEY}in the header`);
		}
	}
}

module.exports = OIDCStrategy;
