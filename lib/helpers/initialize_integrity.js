const { JWK: { isKeyStore, asKeyStore } } = require('node-jose');
const assert = require('assert');
const instance = require('./weak_cache');

async function getKeyStore(conf) {
  if (isKeyStore(conf)) return conf;
  return asKeyStore(conf);
}

module.exports = async function initializeIntegrity(conf) {
  if (instance(this).configuration('features.tokenIntegrity')) {
    const integrity = await getKeyStore(conf);
    assert(integrity.get({ use: 'sig' }), 'at least one signing key must be provided for initialize({ integrity })');
    instance(this).integrity = integrity;
  }
};
