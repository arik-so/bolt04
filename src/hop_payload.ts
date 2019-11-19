import Bigi = require('bigi');
import varuint = require('varuint-bitcoin');

export enum HopPayloadType {
    Legacy,
    TLV
}

export default class HopPayload {
    private type: HopPayloadType;
    private channel_id: Buffer;
    private amount_to_forward: Bigi;
    private outgoing_cltv_value: number;

    constructor({channel_id = Buffer.alloc(0), amount_to_forward = Bigi.valueOf(0), outgoing_cltv_value = 0, type = HopPayloadType.Legacy}: { channel_id?: Buffer, amount_to_forward?: Bigi, outgoing_cltv_value?: number, type?: HopPayloadType }) {
        this.channel_id = channel_id;
        this.amount_to_forward = amount_to_forward;
        this.outgoing_cltv_value = outgoing_cltv_value;
        this.type = type;
    }

    get size(): number {
        return 32;
    }

    get sphinxSize(): number {
        if (this.type === HopPayloadType.Legacy) {
            return 33;
        }

        const payloadLength = this.size;
        return varuint.encodingLength(payloadLength) + payloadLength;
    }

    toDataBuffer(): Buffer {
        if (this.type !== HopPayloadType.Legacy) {
            throw new Error('TLV hop payload type not yet implemented');
        }
        const buffer = Buffer.alloc(32);

        this.channel_id.copy(buffer, 0);

        const amountToForwardBuffer: Buffer = this.amount_to_forward.toBuffer(8);
        amountToForwardBuffer.copy(buffer, 8);

        buffer.writeUInt32BE(this.outgoing_cltv_value, 16);
        return buffer;
    }

    /**
     * Sphinx-encoded buffer with length prefix
     */
    toSphinxBuffer(): Buffer {
        const dataBuffer = this.toDataBuffer();
        if (this.type === HopPayloadType.TLV) {
            return Buffer.concat([varuint.encode(this.size), dataBuffer]);
        }

        return Buffer.concat([Buffer.alloc(1, 0), dataBuffer]);
    }
}