# JSON Sign and verify

## Installation

### node

```shell
npm install --save 'json-sign-and-verify'
```

## Use

### Signing

```javascript
var Signer = require('json-sign-and-verify');
var signer = new Signer({
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\n...\n----END RSA PRIVATE KEY-----'
});
var obj = {foo: 'bar'};

var signedObj = signer.signObj(obj);

var str = '{"foo":"bar"}';

var signedStr = signer.signStr(str);
```

### Verifying

```javascript
var Signer = require('json-sign-and-verify');
var signer = new Signer({
  publicKey: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----'
});
var signedObj = {
  foo: 'bar'
  __jssign_signature: '...'
};

var objectIsVerified = signer.verifyObj(signedObj);

var signedStr = '{"foo":"bar"}:...';

var stringIsVerified = signer.verifyString(signedStr);
```
