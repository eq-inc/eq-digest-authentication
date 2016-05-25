/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */
/*jslint devel: true, node: true, nomen: true, stupid: true */
/*global before, describe, it */
'use strict';



// Variables
const util = require('util'),
    co = require('co'),
    expect = require('expect.js'),
    express = require('express'),
    request = require('superagent'),
    utility = require('karmia-utility'),
    authentication_strategy = require('eq-digest-authentication-strategy'),
    authentication = require('../'),
    port = 30000,
    options = {
        realm: 'eq-digest-auth-strategy-object',
        qop: 'auth'
    },
    users = [
        {
            username: 'test_username',
            password: 'test_password'
        }
    ],
    strategy = authentication_strategy.object(users, options),
    auth = authentication(strategy, options);


// Before
before(function (done) {
    const app = express();
    app.use(auth.middleware());
    app.use(function (req, res) {
        res.status(200).json({success: true});
    });

    app.listen(port);

    done();
});


// Test
describe('Test', function () {
    describe('nonce', function () {
        describe('Should get nonce', function () {
            it('Use strategy', function (done) {
                co(function* () {
                    const nonce = yield auth.nonce();

                    expect(nonce).to.have.length(32);
                    expect(yield auth.strategy.storage.has(nonce)).to.be(true);

                    done();
                });
            });

            it('Not use strategy', function (done) {
                co(function* () {
                    const auth_temporary = authentication({}, options),
                        nonce = yield auth_temporary.nonce();

                    expect(nonce).to.have.length(32);
                    expect(auth_temporary.strategy.storage).to.be(undefined);

                    done();
                });
            });
        });
    });

    describe('challenge', function () {
        it('Should get challenge', function (done) {
            co(function* () {
                const challenge = yield auth.challenge(),
                    result = utility.string.parse(challenge);

                expect(result.Digest).to.be('Digest');
                expect(result.nonce).to.have.length(32);
                expect(result.realm).to.be(options.realm);
                expect(result.qop).to.be(options.qop);
                expect(result.userhash).to.be('false');

                done();
            });
        });
    });

    describe('reaponse', function () {
        it('Should get response', function (done) {
            const req = {
                    method: 'POST'
                },
                parameters = {
                    algorithm: 'sha-256',
                    realm: options.realm,
                    uri: '/',
                    nonce: 'NONCE',
                    nc: '000001',
                    cnonce: 'CNONCE',
                    qop: 'auth'
                },
                response = auth.response(req, parameters, users[0]);

            expect(response).to.have.length(64);

            done();
        });
    });

    describe('middleware', function () {
        it('Should login', function (done) {
            const url = util.format('http://localhost:%d', port);
            request.get(url).end(function (error) {
                const req = {method: 'GET'},
                    challenge = utility.string.parse(error.response.headers['www-authenticate']),
                    parameters = {
                        algorithm: 'sha-256',
                        realm: challenge.realm,
                        nonce: challenge.nonce,
                        uri: '/',
                        qop: challenge.qop,
                        cnonce: 'CNONCE',
                        nc: '000001'
                    },
                    response = auth.response(req, parameters, users[0]),
                    authorization = util.format(
                        'Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=%s, response="%s", qop="%s", nc="%s", cnonce="%s"',
                        users[0].username,
                        parameters.realm,
                        parameters.nonce,
                        parameters.uri,
                        parameters.algorithm,
                        response,
                        parameters.qop,
                        parameters.nc,
                        parameters.cnonce
                    );
                request.get(url).set('authorization', authorization).end(function (error, result) {
                    if (error) {
                        return done(error);
                    }

                    expect(result.body).to.eql({success: true});

                    done();
                });
            });
        });
    });
});



/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
