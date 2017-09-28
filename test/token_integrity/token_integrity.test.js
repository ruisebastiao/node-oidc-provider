const sinon = require('sinon');
const tokenHash = require('oidc-token-hash');
const { expect } = require('chai');
const bootstrap = require('../test_helper');
const { decode, encode } = require('base64url');

describe('tokenIntegrity feature (ChecksumToken)', () => {
  before(bootstrap(__dirname)); // provider

  afterEach(function () {
    this.adapter.find.reset();
    this.adapter.upsert.reset();
  });

  before(function () {
    this.adapter = this.TestAdapter.for('AccessToken');
    sinon.spy(this.adapter, 'find');
    sinon.spy(this.adapter, 'upsert');
  });

  after(function () {
    this.adapter.find.restore();
    this.adapter.upsert.restore();
  });

  it('it keeps a checksum of a value only returned to the client', async function () {
    const token = await new this.provider.AccessToken({
      grantId: 'foo',
    }).save();

    expect(this.adapter.upsert.called).to.be.true;
    const [, { header, payload }] = this.adapter.upsert.firstCall.args;
    const { kid } = JSON.parse(decode(header));
    const { checksum } = JSON.parse(decode(payload));
    expect(kid).to.be.ok;
    expect(checksum).to.equal(tokenHash.generate(token.substring(48, 59)));
    expect(await this.provider.AccessToken.find(token)).to.be.ok;
  });

  it('prevents from DB manipulation of token properties (i.e. exp)', async function () {
    const token = await new this.provider.AccessToken({
      grantId: 'foo',
    }).save();
    const jti = token.substring(0, 48);
    const stored = this.adapter.syncFind(jti);
    const manipulated = JSON.parse(decode(stored.payload));
    manipulated.exp += 100;
    stored.payload = encode(JSON.stringify(manipulated));
    expect(await this.provider.AccessToken.find(token)).to.be.undefined;
  });

  it('prevents from DB manipulation of token signatures', async function () {
    const token = await new this.provider.AccessToken({
      grantId: 'foo',
    }).save();
    const jti = token.substring(0, 48);
    const stored = this.adapter.syncFind(jti);
    stored.signature = 'foo';
    expect(await this.provider.AccessToken.find(`${token.substring(0, 59)}foo`)).to.be.undefined;
  });

  it('prevents reconstructing tokens from DB without having client DB dumps', async function () {
    const token = await new this.provider.AccessToken({
      grantId: 'foo',
    }).save();
    expect(await this.provider.AccessToken.find(`${token.substring(0, 48)}elevenchars${token.substring(59)}`)).to.be.undefined;
  });

  it('returns undefined for not found tokens', async function () {
    expect(await this.provider.AccessToken.find('MDQ0OWNjM2YtMzgzYi00M2FmLWJiNWItYWRhZjBjY2Y1ODY10FJ-UgHXVVUXSS-G5c8rn-YsfV4OlH5e1f_MneAvRyqwV6rIvC2Uq0')).to.be.undefined;
    expect(this.adapter.find.calledOnce).to.be.true;
  });

  it('assigns returned consumed prop', async function () {
    const token = await new this.provider.AccessToken({
      grantId: 'foo',
    }).save();
    const jti = token.substring(0, 48);
    const stored = this.adapter.syncFind(jti);
    stored.consumed = true;
    expect(await this.provider.AccessToken.find(token)).to.have.property('consumed', true);
  });
});
