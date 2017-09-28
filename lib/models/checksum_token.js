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
    async getValueAndPayload() {
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

    static async validateStored(token, { header, payload, signature }, { ignoreExpiration }) {
      const jwt = [header, payload, signature].join('.');
      const { payload: decoded } = JWT.decode(jwt);
      assert(constantEquals(Buffer.from(token.substring(59)), Buffer.from(signature)));
      assert(tokenHash(decoded.checksum, token.substring(48, 59)));

      const keystore = instance(provider).integrity;
      await JWT.verify(
        jwt,
        keystore,
        { ignoreExpiration, issuer: provider.issuer },
      );
      return decoded;
    }
  };
};
