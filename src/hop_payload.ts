import Bigi = require('bigi');
import varuint = require('varuint-bitcoin');

export enum HopPayloadType {
	Legacy,
	TLV
}

export default class HopPayload {
	private type: HopPayloadType;
	private channelId: Buffer;
	private amountToForward: Bigi;
	private outgoingCltvValue: number;

	constructor({channel_id = Buffer.alloc(0), amount_to_forward = Bigi.valueOf(0), outgoing_cltv_value = 0, type = HopPayloadType.Legacy}: { channel_id?: Buffer, amount_to_forward?: Bigi, outgoing_cltv_value?: number, type?: HopPayloadType }) {
		this.channelId = channel_id;
		this.amountToForward = amount_to_forward;
		this.outgoingCltvValue = outgoing_cltv_value;
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

		this.channelId.copy(buffer, 0);

		const amountToForwardBuffer: Buffer = this.amountToForward.toBuffer(8);
		amountToForwardBuffer.copy(buffer, 8);

		buffer.writeUInt32BE(this.outgoingCltvValue, 16);
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

	/**
	 *
	 * @param undelimitedHopPayloads
	 */
	static fromSphinxBuffer(undelimitedHopPayloads: Buffer): HopPayload {
		const firstByte = undelimitedHopPayloads[0];
		if (firstByte === 0) {
			// this is a legacy
			const sphinxBuffer = undelimitedHopPayloads.slice(0, 33);
			const dataBuffer = sphinxBuffer.slice(1);
			const channelId = dataBuffer.slice(0, 8);
			const amountToForward = Bigi.fromBuffer(dataBuffer.slice(8, 16));
			const outgoingCltvValue = dataBuffer.readUInt32BE(16);
			return new HopPayload({
				type: HopPayloadType.Legacy,
				channel_id: channelId,
				amount_to_forward: amountToForward,
				outgoing_cltv_value: outgoingCltvValue
			});
		} else {
			const length = varuint.decode(undelimitedHopPayloads);
			const lengthEncodingLength = varuint.encodingLength(length);
			const sphinxBuffer = undelimitedHopPayloads.slice(0, length + lengthEncodingLength);
			const dataBuffer = sphinxBuffer.slice(lengthEncodingLength);
			throw new Error('TLV decoding not supported yet');
		}
	}
}
