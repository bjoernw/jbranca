# jbranca 
[![CircleCI](https://circleci.com/gh/bjoernw/jbranca/tree/master.svg?style=svg)](https://circleci.com/gh/bjoernw/jbranca/tree/master)

JBranca is a Java library to create Branca tokens. Branca tokens are an improvement on the no longer maintained Fernet token.

### What is a Branca Token?

Branca is a secure easy to use token format which makes it hard to shoot yourself in the foot. It uses IETF XChaCha20-Poly1305 AEAD symmetric encryption to create encrypted and tamperproof tokens. Payload itself is an arbitrary sequence of bytes. You can use for example a JSON object, plain text string or even binary data serialized by MessagePack or Protocol Buffers.

### Token Structure
`Version (1B) || Timestamp (4B) || Nonce (24B) || Ciphertext (*B) || Tag (16B)`

### Why?
* Secure
* Easy to implement
* Small token size

### What about JWTs?
Since a Branca token is an authenticated and encrypted wrapper around an arbitrary payload you could make a JWT the payload and benefit from not having to worry about JOSE and the small token size.
You could decrease the token size even further by using [Protocol Buffers](https://developers.google.com/protocol-buffers) or [Message Pack](https://msgpack.org) for your payload.

### Example
```java
    byte[] key = new byte[32];
    new Random().nextBytes(key);
    
    BrancaTokenFactory factory = new BrancaTokenFactory(key);
    String plaintext = "{\"imajwt\": \"imajwt\"}";
    byte[] encoded = factory.seal(plaintext.getBytes());
    byte[] decoded = factory.open(encoded);
    Assert.assertEquals(plaintext, new String(decoded));
```

### Spec
https://github.com/tuupola/branca-spec

Encryption Library: Bouncycastle

