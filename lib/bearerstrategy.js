/*
DESCRIPTION
IDCS server's passport bearer authentication strategy.

MODIFIED    (MM/DD/YY)
junyhe      01/04/17 - Creation
 */
'use strict';

// core module
const passport = require('passport');

// project module
const Logger = require('./logger');
const CONSTANTS = require('./constants');
const TokenManager = require('./idcstokenmanager');
const UserManager = require('./idcsusermanager');

// bearer token header name
const BEARER_TOKEN_HEADER_KEY = 'authorization';

// resource tenant header name
const RESOURCE_TENANT_HEADER_KEY = 'x-resource-identity-domain-name';

class BearerStrategy extends passport.Strategy {
	/**
	 * Constructor for bearer access token assertion strategy
	 *  @constructor
	 *  @param {Object}       options Configurations for idcs bearer strategy.
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
		this.name = 'Bearer';
		this.verify = verify;

		Logger.setLevel(this.options[CONSTANTS.LOG_LEVEL]);
		this.logger = Logger.getLogger('Bearer');
		this.logger.trace(`constructor, options: ${options}, options after handling: ${this.options}`);

		this.oauthClientOptions = {
			clientId: this.options[CONSTANTS.CLIENT_ID],
			clientSecret: this.options[CONSTANTS.CLIENT_SECRET],
			tokenTimeoutWindow: this.options[CONSTANTS.TOKEN_TIMEOUT_WINDOW],
			clientTenant: this.options[CONSTANTS.CLIENT_TENANT]
		};

		let verifyClaims = {
			clockTolerance: this.options[CONSTANTS.TOKEN_CLOCK_SKEW]
		};
		if (this.options[CONSTANTS.TOKEN_CLAIM_ISSUER]) {
			verifyClaims.issuer = this.options[CONSTANTS.TOKEN_CLAIM_ISSUER];
		}

		this.metadataUrl = `${this.options[CONSTANTS.IDCSHost]}${CONSTANTS.DISCOVERY_PATH}`;
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

		let tenant = req.headers[RESOURCE_TENANT_HEADER_KEY];
		let at = null;
		// get token from headers
		this.logger.trace(`req.headers[BEARER_TOKEN_HEADER_KEY]: ${JSON.stringify(req.headers[BEARER_TOKEN_HEADER_KEY])}`);
		if (req.headers[BEARER_TOKEN_HEADER_KEY]) {
			let atValues = req.headers[BEARER_TOKEN_HEADER_KEY].split(' ');
			if (atValues.length == 2 && atValues[0].toLowerCase() === 'bearer') {
				at = atValues[1];
			}
		}

		if (!at) {
			return this.fail(`missing token in the header["${BEARER_TOKEN_HEADER_KEY}"] or body.token`);
		}

		let oidc = this;
		let opts = this.options;
		let complete = function(err, user){
			if(err){
				oidc.fail(err);
			}else{
				oidc.success(user)
			}
		};
		let um = new UserManager(opts);
		um.assertClaims(at).then(function(res){
			oidc.verify(res.token, res.token.user_tenantname, res.result, complete);
		}).catch(function(err){
			oidc.fail(err);
		});
	}
}

module.exports = BearerStrategy;
