const { clone } = require('lodash');
const config = clone(require('../default.config'));

config.features = { tokenIntegrity: false };

module.exports = {
  config,
};
