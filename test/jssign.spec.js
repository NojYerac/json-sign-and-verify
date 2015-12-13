var should = require('should');
var JsSigner = require('../jssign');
var fs = require('fs');
var jsSigner, jsSignerPub, signedTestObj, signedTestString;
var testObj = {
  these: 'those',
  foo: 'bar',
  baz: 'bof',
  some: ['values', 'in', 'an', 'array']
};
var testString = 'This is a test string. which contains a ":"';
var sigRE = /^[a-zA-Z0-9\/+]+={0,2}$/;
describe('JsSigner class', function() {
  before(function(done) {
    var config = {};
    var priv = new Promise(function(resolve, reject) {
      fs.readFile('./priv.pem', function(error, key) {
        if (error) return reject(error);
        config.privateKey = key.toString();
        resolve(config.privateKey);
      });
    });

    var pub = new Promise(function(resolve, reject) {
      fs.readFile('./pub.pem', function(error, key) {
        if (error) return reject(error);
        config.publicKey = key.toString();
        resolve(config.publicKey);
      });
    });

    Promise.all([priv, pub]).then(function() {
      jsSigner = new JsSigner({privateKey: config.privateKey});
      should(jsSigner.privateKey).not.be.Null();
      should(jsSigner.publicKey).not.be.Null();
      jsSignerPub = new JsSigner({publicKey: config.publicKey});
      should(jsSignerPub.privateKey).be.Null();
      should(jsSignerPub.publicKey).not.be.Null();
      done();
    }).catch(done);
  });

  describe('signObj method', function() {
    it('should sign the testObj', function() {
      signedTestObj = jsSigner.signObj(testObj);
      signedTestObj.should.have.property('__jssign_signature')
        .which.is.an.instanceOf(String)
        .and.match(sigRE);
      // console.log(signedTestObj);
    });
  });

  describe('verifyObj method', function() {
    it('should verify the signature', function() {
      var verified = jsSigner.verifyObj(JSON.parse(JSON.stringify(signedTestObj)));
      verified.should.equal(true);
    });

    it('should resist tampering', function() {
      signedTestObj.these = 'ones';
      var verified = jsSigner.verifyObj(JSON.parse(JSON.stringify(signedTestObj)));
      verified.should.equal(false);
    });
  });

  describe('signString method', function() {
    it('should sign the testString', function() {
      signedTestString = jsSigner.signString(testString);
      signedTestString.indexOf(testString).should.equal(0);
      signedTestString.lastIndexOf(':').should.equal(testString.length);
      signedTestString.slice(testString.length + 1).should.match(sigRE);
    });
  });

  describe('signString method', function() {
    it('should verify the signed testString', function() {
      var verified = jsSigner.verifyString(signedTestString);
      verified.should.equal(true);
    });

    it('should resist tampering', function() {
      signedTestString = signedTestString.replace('test', 'sample');
      var verified = jsSigner.verifyString(signedTestString);
      verified.should.equal(false);
    });
  });
});
