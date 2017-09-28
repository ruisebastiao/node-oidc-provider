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

    static async validateStored(tokenValue, stored, { ignoreExpiration }) {
      assert(constantEquals(Buffer.from(tokenValue.substring(48)), Buffer.from(stored.signature)));
      const { payload } = JWT.decode([stored.header, stored.payload, stored.signature].join('.'));
      JWT.assertPayload(payload, { ignoreExpiration, issuer: provider.issuer });
      return payload;
    }

    static async find(tokenValue = '', { ignoreExpiration = false } = {}) {
      try {
        const jti = tokenValue.substring(0, 48);
        assert(jti);
        const token = await this.adapter.find(jti);
        assert(token);
        const payload = await this.validateStored(tokenValue, token, { ignoreExpiration });
        const inst = new this(Object.assign(payload));
        if (token.consumed !== undefined) inst.consumed = token.consumed;

        return inst;
      } catch (err) {
        return undefined;
      }
    }
  };
};
