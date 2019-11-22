# bolt04
[![Build Status](https://travis-ci.com/arik-so/bolt04.svg?branch=master)](https://travis-ci.com/arik-so/bolt04)

A utility for Lightning Network's BOLT 4 specification. 

## Install

```shell script
npm install bolt04
```

## Examples

### HopPayload

```typescript
import {HopPayload, HopPayloadType} from 'bolt04';

const payload = new HopPayload({
    type: HopPayloadType.Legacy,
    channel_id: Buffer.alloc(8, 10),
    amount_to_forward: 11,
    outgoing_cltv_value: 12
});

const payloadBuffer = payload.toSphinxBuffer();
console.log(payloadBuffer.toString('hex'));
// 000a0a0a0a0a0a0a0a000000000000000b0000000c000000000000000000000000
```

### Sphinx Onion

To construct and peel Sphinx onions, we first need some imports:

```typescript
import {HopPayload, SharedSecret, Sphinx} from 'bolt04';
```

#### Construct the onion

Before we can construct the onion, we need to know the session key and the hop public keys.

```typescript
const sessionKey = Buffer.from('4141414141414141414141414141414141414141414141414141414141414141', 'hex');
const hopPublicKeys = [
    Buffer.from('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619', 'hex'),
    Buffer.from('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c', 'hex'),
    Buffer.from('027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007', 'hex'),
    Buffer.from('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991', 'hex'),
    Buffer.from('02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145', 'hex')
];
```

Equipped with those, we can calculate the per-hop shared secrets.

```typescript
const sharedSecrets = SharedSecret.calculateSharedSecrets({sessionKey, hopPublicKeys});
```

Now we specify the actual data we're gonna send. In this example, we generate some hop payloads with monotonically
increasing values for their various fields.

```typescript
const payloads = [];
for (let i = 0; i < 5; i++) {
    const currentChannelId = Buffer.alloc(8, i);
    const currentPayload = new HopPayload({
        channel_id: currentChannelId,
        amount_to_forward: i,
        outgoing_cltv_value: i
    });
    payloads.push(currentPayload);
}
```

Now we can finally construct the onion itself. We will also settle on some associated data that will be sent out of 
bounds, which is an additional component of the hash preimage for data inegrity validation.

```typescript
const associatedData = Buffer.from('4242424242424242424242424242424242424242424242424242424242424242', 'hex');
const onion = Sphinx.constructOnion({
    sharedSecrets, payloads, associatedData, firstHopPublicKey: hopPublicKeys[0]
});
console.log(onion.toBuffer().toString('hex')); // 0002eec7245d6b7…cff954949076dcf (see test/sphinx)
```

#### Peel a layer

```typescript
const onion = Buffer.from('0002eec7245d6b7…cff954949076dcf', 'hex'); // see test/sphinx
const sphinx = Sphinx.fromBuffer(onion);

// we need our private key and the associated data
const hopPrivateKey = Buffer.from('4141414141414141414141414141414141414141414141414141414141414141', 'hex');
const associatedData = Buffer.from('4242424242424242424242424242424242424242424242424242424242424242', 'hex');

const peel0 = sphinx.peel({hopPrivateKey: hopPrivateKey, associatedData});
const nextLayer = peel0.sphinx; // not null if we are not the final recipient, hence we can call nextLayer.peel()
console.log(nextLayer.toBuffer().toString('hex')); // 00028f9438bfbf7…cd4fe26a492d376

const hopPayload = peel0.hopPayload;
console.log(hopPayload.channelId.toString('hex')); // 0000000000000000
console.log(hopPayload.amountToForward); // 0n
console.log(hopPayload.outgoingCltvValue); // 0
```

## License

MIT
