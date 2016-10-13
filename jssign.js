var RSA = require('node-rsa');
var _ = require('lodash');
module.exports = JsSigner;

/**
 * Returns a new JsSigner object
 * @param {object} config supply the private or public key with format:
 *                        {
 *                          privateKey: {string} private key for signing and verifing
 *                          publicKey: {string} key for verifing only
 *                        }
 */
function JsSigner(config) {
  var self = this;
  var priv = config.privateKey ? new RSA(config.privateKey) : null;
  var pub = config.publicKey ? new RSA(config.publicKey) : null;
  if (!_.isNull(priv) && _.isNull(pub)) {
    pub = new RSA(priv.exportKey('public'));
  }
  _.extend(self, {
    get privateKey() {return priv;},
    set privateKey(key) {
      priv = new RSA(key);
      pub = pub || new RSA(priv.exportKey('public'));
    },
    get publicKey() {return pub;},
    set publicKey(key) {pub = new RSA(key);},
    signObj: signObj,
    verifyObj: verifyObj,
    signString: signString,
    verifyString: verifyString
  });

  /**
   * Returns the object signed with the private key
   * @param  {object} json the JSON object to be signed
   * @return {object}      the signed JSON object
   */
  function signObj(j) {
    if (_.isNull(self.privateKey)) {
      throw new Error('No private key');
    }
    var json = {};
    Object.keys(j).sort().forEach(k => {
      json[k] = j[k];
    });
    var jsonString = JSON.stringify(json);
    json.__jssign_signature = self.privateKey.sign(jsonString, 'base64', 'utf-8');
    return json;
  }

  /**
   * Returns true if the signature is verified
   * @param  {object} json the JSON object to be verified
   * @return {boolean}     true if the signature is valid
   */
  function verifyObj(j) {
    if (_.isNull(self.publicKey)) {
      throw new Error('No public key');
    }
    var json = {};
    var signature = j.__jssign_signature;
    Object.keys(j).sort().forEach(k => {
      if (k === "__jssign_signature") {return;}
      json[k] = j[k];
    });
    var jsonString = JSON.stringify(json);
    return self.publicKey.verify(jsonString, signature, 'utf-8', 'base64');
  }

  /**
   * Returns the string signed with the private key
   * @param  {string} string the string to sign
   * @return {string}        the signed string
   */
  function signString(string) {
    if (_.isNull(self.privateKey)) {
      throw new Error('No private key');
    }
    return `${string}:${self.privateKey.sign(string, 'base64')}`;
  }

  /**
   * Returns true if the signature is verified
   * @param  {string} signedString the string to be verified
   * @return {boolean}             true if the signature is valid
   */
  function verifyString(signedString) {
    if (_.isNull(self.publicKey)) {
      throw new Error('No public key');
    }
    var index = signedString.lastIndexOf(':');
    var string = signedString.slice(0, index),
      signature = signedString.slice(index + 1);
    return self.publicKey.verify(string, signature, 'utf-8', 'base64');
  }
}
