# bolt04
[![Build Status](https://travis-ci.com/arik-so/bolt04.svg?branch=master)](https://travis-ci.com/arik-so/bolt04)

A utility for Lightning Network's BOLT 4 specification.

## Install

```shell script
npm install bolt04
```

## Use

```typescript
import {HopPayload, HopPayloadType, Bigi} from 'bolt04';

const payload = new HopPayload({
    type: HopPayloadType.Legacy,
    channel_id: Buffer.alloc(8, 10),
    amount_to_forward: Bigi.valueOf(11),
    outgoing_cltv_value: 12
});

const payloadBuffer = payload.toSphinxBuffer();
console.log(payloadBuffer.toString('hex'));
// 000a0a0a0a0a0a0a0a000000000000000b0000000c000000000000000000000000
```

## License

MIT
