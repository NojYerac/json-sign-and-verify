var RSA = require('node-rsa');
var _ = require('lodash');
module.exports = JsSigner;

/**
 * [JsSigner description]
 * @param {[type]} config [description]
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
   * [signObj description]
   * @param  {[type]} json [description]
   * @return {[type]}      [description]
   */
  function signObj(json) {
    if (_.isNull(self.privateKey)) throw new Error('No private key');
    var jsonString = JSON.stringify(json);
    json.__jssign_signature = self.privateKey.sign(jsonString, 'base64', 'utf-8');
    return json;
  }

  /**
   * [verifyObj description]
   * @param  {[type]} json [description]
   * @return {[type]}      [description]
   */
  function verifyObj(json) {
    var signature = json.__jssign_signature;
    delete json.__jssign_signature;
    var jsonString = JSON.stringify(json);
    return self.publicKey.verify(jsonString, signature, 'utf-8', 'base64');
  }

  /**
   * [signString description]
   * @param  {[type]} string [description]
   * @return {[type]}        [description]
   */
  function signString(string) {
    if (_.isNull(self.privateKey)) throw new Error('No private key');
    return `${string}:${self.privateKey.sign(string, 'base64')}`;
  }

  /**
   * [verifyString description]
   * @param  {[type]} signedString [description]
   * @return {[type]}              [description]
   */
  function verifyString(signedString) {
    var index = signedString.lastIndexOf(':');
    var string = signedString.slice(0, index),
      signature = signedString.slice(index +1);
    return self.publicKey.verify(string, signature, 'utf-8', 'base64');
  }
}
