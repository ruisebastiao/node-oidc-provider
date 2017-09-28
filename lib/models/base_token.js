const IN_PAYLOAD = [
  'accountId',
  'acr',
  'amr',
  'authTime',
  'claims',
  'clientId',
  'codeChallenge', // for authorization code
  'codeChallengeMethod', // for authorization code
  'grantId',
  'jti',
  'kind',
  'nonce',
  'redirectUri',
  'scope',
  'sid',
];

const { promisify } = require('util');
const { pick } = require('lodash');
const constantEquals = require('buffer-equals-constant');
const assert = require('assert');
const base64url = require('base64url');
const uuid = require('uuid');

const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');
const JWT = require('../helpers/jwt');
const randomBytes = promisify(require('crypto').randomBytes);

const adapterCache = new WeakMap();

module.exports = function getBaseToken(provider) {
  function adapter(ctx) {
    const obj = typeof ctx === 'function' ? ctx : ctx.constructor;

    if (!adapterCache.has(obj)) {
      adapterCache.set(obj, new (instance(provider).Adapter)(obj.name));
    }

    return adapterCache.get(obj);
  }

  return class BaseToken {
    constructor(payload) {
      Object.assign(this, payload);

      this.jti = this.jti || base64url.encode(uuid());

      this.kind = this.kind || this.constructor.name;
      assert.equal(this.kind, this.constructor.name, 'kind mismatch');
    }

    get expiration() { return this.expiresIn || this.constructor.expiresIn; }
    static get expiresIn() { return instance(provider).configuration(`ttl.${this.name}`); }
    get isValid() { return !this.consumed && !this.isExpired; }
    get isExpired() { return this.exp <= epochTime(); }

    async getTokenAndPayload() {
      const [jwt, random] = await Promise.all([
        JWT.sign(pick(this, this.constructor.IN_PAYLOAD), undefined, 'none', {
          expiresIn: this.expiration,
          issuer: provider.issuer,
        }),
        randomBytes(64),
      ]);

      const [header, payload,, signature] = [...jwt.split('.'), base64url(random)];
      return [{
        header,
        payload,
        signature,
      }, `${this.jti}${signature}`];
    }

    async save() {
      const [upsert, tokenValue] = await this.getTokenAndPayload();

      if (this.grantId) upsert.grantId = this.grantId;
      await this.adapter.upsert(this.jti, upsert, this.expiresIn);
      provider.emit('token.issued', this);

      return tokenValue;
    }

    destroy() {
      provider.emit('token.revoked', this);
      if (this.grantId) provider.emit('grant.revoked', this.grantId);

      return this.adapter.destroy(this.jti);
    }

    consume() {
      provider.emit('token.consumed', this);
      return this.adapter.consume(this.jti);
    }

    static get adapter() {
      return adapter(this);
    }

    get adapter() {
      return adapter(this);
    }

    static get IN_PAYLOAD() { return IN_PAYLOAD; }

    static fromJWT(jwt, { ignoreExpiration = false, issuer = provider.issuer } = {}) {
      const { payload } = JWT.decode(jwt);
      JWT.assertPayload(payload, { ignoreExpiration, issuer });
      return new this(Object.assign(payload));
    }

    static async find(tokenValue, { ignoreExpiration = false } = {}) {
      let jti;
      let sig;

      try {
        jti = tokenValue.substring(0, 48);
        sig = tokenValue.substring(48);
        assert(jti);
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
        const validated = this.fromJWT(jwt, { ignoreExpiration });
        if (token.consumed !== undefined) validated.consumed = token.consumed;
        return validated;
      } catch (err) {
        return undefined;
      }
    }
  };
};
