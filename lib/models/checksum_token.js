const assert = require('assert');
const { promisify } = require('util');
const { pick } = require('lodash');
const tokenHash = require('oidc-token-hash');
const base64url = require('base64url');
const constantEquals = require('buffer-equals-constant');
const randomBytes = promisify(require('crypto').randomBytes);
const JWT = require('../helpers/jwt');
const instance = require('../helpers/weak_cache');

module.exports = function extendBaseToken(provider) {
  const { BaseToken } = provider;

  return class ChecksumToken extends BaseToken {
    async getTokenAndPayload() {
      const checksumToken = base64url(await randomBytes(8));
      const key = instance(provider).integrity.get();
      const jwt = await JWT.sign(Object.assign(pick(this, this.constructor.IN_PAYLOAD), {
        checksum: tokenHash.generate(checksumToken),
      }), key, key.alg, {
        expiresIn: this.expiration,
        issuer: provider.issuer,
        reference: true,
      });

      const [header, payload, signature] = jwt.split('.');
      return [{
        header,
        payload,
        signature,
      }, `${this.jti}${checksumToken}${signature}`];
    }

    static async fromJWT(jwt, { ignoreExpiration = false, issuer = provider.issuer } = {}) {
      const keystore = instance(provider).integrity;
      const result = await JWT.verify(jwt, keystore, { ignoreExpiration, issuer });
      return new this(Object.assign(result.payload));
    }

    static async find(tokenValue, { ignoreExpiration = false } = {}) {
      let jti;
      let sig;
      let checksumToken;

      try {
        jti = tokenValue.substring(0, 48);
        checksumToken = tokenValue.substring(48, 59);
        sig = tokenValue.substring(59);
        assert.equal(jti.length, 48);
        assert.equal(checksumToken.length, 11);
        assert(sig);
      } catch (err) {
        return undefined;
      }

      const token = await this.adapter.find(jti);
      if (!token) return undefined;

      /* istanbul ignore if */
      if (!constantEquals(Buffer.from(sig), Buffer.from(token.signature))) {
        return undefined;
      }

      const jwt = [token.header, token.payload, token.signature].join('.');
      try {
        const validated = await this.fromJWT(jwt, { ignoreExpiration });
        assert(tokenHash(validated.checksum, checksumToken));
        const result = validated;
        if (token.consumed !== undefined) result.consumed = token.consumed;
        return result;
      } catch (err) {
        return undefined;
      }
    }
  };
};
