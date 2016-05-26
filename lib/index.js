/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */
/*jslint devel: true, node: true, nomen: true, stupid: true */
'use strict';



// Variables
const util = require('util'),
    _ = require('lodash'),
    co = require('co'),
    utility = require('karmia-utility');


/**
 * StrategyObject
 *
 * @class
 */
class EqDigestAuthentication {

    /**
     * Constructor
     *
     * @constructs KarmiaContext
     */
    constructor(strategy, options) {
        const self = this;
        self.strategy = strategy;
        self.options = options;

        self.realm = self.options.realm;
        self.domain = self.options.domain;
        self.opaque = self.options.opaque;
        self.algorithm = self.options.algorithm;
        self.qop = self.options.qop;
        self.charset = self.options.charset;
        self.userhash = self.options.userhash;
    }

    /**
     * Generate nonce
     *
     * @returns {string}
     */
    nonce() {
        const self = this;
        if (_.isFunction(self.strategy.nonce)) {
            return self.strategy.nonce(self);
        }

        return Promise.resolve(utility.random.string(32, {special: false}));
    }

    /**
     * Generate www-authenticate header content
     *
     * @return string
     */
    challenge() {
        const self = this;

        return co(function*() {
            const nonce = yield self.nonce();
            let result = util.format('Digest realm="%s"', self.realm);

            // Add domain parameter
            if (self.domain) {
                const domain = _.isArray(self.domain) ? self.domain.join(' ') : self.domain;
                result = util.format('%s, domain="%s"', result, domain);
            }

            // Add nonce parameter
            result = util.format('%s, nonce="%s"', result, nonce);

            // Add opaque parameter
            if (self.opaque) {
                result = util.format('%s, opaque="%s"', result, self.opaque);
            }

            // Add algorithm parameter
            if (self.algorithm) {
                result = util.format('%s, algorithm=%s', result, self.algorithm);
            }

            // Add qop parameter
            if (self.qop) {
                result = util.format('%s, qop="%s"', result, self.qop);
            }

            // Add charset parameter
            if (self.charset) {
                result = util.format('%s, charset="UTF-8"', result);
            }

            // Add userhash parameter
            result = util.format('%s, userhash="%s"', result, self.userhash ? 'true' : 'false');

            return result;
        });
    }

    /**
     * Generate response
     *
     * @param {Object} req
     * @param {Object} parameters
     * @param {Object} credential
     */
    response(req, parameters, credential) {
        const self = this,
            realm = self.realm,
            algorithm = (parameters.algorithm || 'md5').toLowerCase().replace('sha-', 'sha').replace('-sess', ''),
            username = credential.username,
            password = credential.password,
            nonce = parameters.nonce,
            uri = parameters.uri,
            nc = parameters.nc,
            cnonce = parameters.cnonce,
            qop = parameters.qop || '';

        let a1;
        if (-1 === (parameters.algorithm || 'md5').toLowerCase().indexOf('-sess')) {
            a1 = util.format('%s:%s:%s', username, realm, password);
        } else {
            a1 = util.format('%s:%s:%s:%s', username, realm, password, nonce, cnonce);
        }

        let a2;
        if ('auth-int' === qop.toLowerCase()) {
            a2 = util.format(
                '%s:%s:%s',
                req.method,
                uri,
                utility.crypto.hash(algorithm, req.body).toString('hex'));
        } else {
            a2 = util.format('%s:%s', req.method, uri);
        }

        return utility.crypto.hash(algorithm, util.format(
            '%s:%s:%s:%s:%s:%s',
            utility.crypto.hash(algorithm, a1).toString('hex'),
            nonce,
            nc,
            cnonce,
            qop,
            utility.crypto.hash(algorithm, a2).toString('hex'))).toString('hex');
    }

    /**
     * Return middleware function
     *
     * @returns {Function}
     */
    middleware() {
        const self = this;

        return function (req, res, next) {
            co(function* () {
                const parameters = utility.string.parse(req.header('authorization') || '');
                if ('digest' !== (parameters.Digest || '').toLowerCase()) {
                    return Promise.reject();
                }

                const secret = yield self.strategy.secret(self, parameters),
                    response = self.response(req, parameters, secret);
                if (response === parameters.response) {
                    if (_.isFunction(self.strategy.validate)) {
                        return yield self.strategy.validate(self, parameters, secret);
                    }

                    return Promise.resolve();
                }

                return Promise.reject();
            }).then(function () {
                next();
            }).catch(function () {
                self.challenge().then(function (result) {
                    res.header('WWW-Authenticate', result);
                    res.sendStatus(401);
                }).catch(next);
            });
        };
    }
}


// Export module
module.exports = function (strategy, options) {
    if (_.isObject(strategy) && strategy.strategy) {
        options = strategy;
        strategy = options.strategy;
    }

    return new EqDigestAuthentication(strategy, options || {});
};



/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
