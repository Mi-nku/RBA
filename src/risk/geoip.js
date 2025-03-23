const maxmind = require('maxmind');
const { promisify } = require('util');
const config = require('../risk/config.js');

const _openDatabase = (path) => {
  return promisify(maxmind.open)(path);
};

const getGeoInfo = async (ip) => {
  const [asnLookup, countryLookup] = await Promise.all([
    _openDatabase(config.maxmind.asnPath),
    _openDatabase(config.maxmind.countryPath)
  ]);

  return {
    ip,
    asn: asnLookup.get(ip)?.autonomous_system_number,
    cc: countryLookup.get(ip)?.country?.iso_code
  };
};

module.exports = {
  _openDatabase,
  getGeoInfo
};