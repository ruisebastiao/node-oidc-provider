/* eslint-disable no-new */

const jose = require('node-jose');
const { expect } = require('chai');
const Provider = require('../../lib');

const fail = () => { throw new Error('expected promise to be rejected'); };

describe('configuration.integrity', () => {
  it('must contain at least one signing key (keystore instance)', () => {
    const integrity = jose.JWK.createKeyStore();
    const provider = new Provider('http://localhost', { features: { tokenIntegrity: true } });

    return provider.initialize({ integrity }).then(fail, (err) => {
      expect(err.message).to.equal('at least one signing key must be provided for initialize({ integrity })');
    }).then(() => integrity.generate('RSA', 256)).then(() => {
      provider.initialize({ integrity });
    });
  });

  it('must contain at least one signing key (jwks)', () => {
    const integrity = jose.JWK.createKeyStore();
    const provider = new Provider('http://localhost', { features: { tokenIntegrity: true } });

    return provider.initialize({ integrity: integrity.toJSON(true) }).then(fail, (err) => {
      expect(err.message).to.equal('at least one signing key must be provided for initialize({ integrity })');
    }).then(() => integrity.generate('RSA', 256)).then(() => {
      provider.initialize({ integrity: integrity.toJSON(true) });
    });
  });
});
