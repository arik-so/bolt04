import Bigi = require('bigi');
import varuint = require('varuint-bitcoin');
import {VarInt, TypeHandler} from 'lightning-tlv';
import TLV from 'lightning-tlv/src/tlv';

export enum HopPayloadType {
	Legacy,
	TLV
}

export enum HopPayloadTLVTypes {
	AMOUNT_TO_FORWARD = 2,
	OUTGOING_CLTV_VALUE = 4,
	SHORT_CHANNEL_ID = 6
}

export default class HopPayload {
	private type: HopPayloadType;
	public readonly channelId: Buffer;
	public readonly amountToForward: Bigi;
	public readonly outgoingCltvValue: number;

	constructor({channel_id = Buffer.alloc(0), amount_to_forward = Bigi.valueOf(0), outgoing_cltv_value = 0, type = HopPayloadType.Legacy}: { channel_id?: Buffer, amount_to_forward?: Bigi, outgoing_cltv_value?: number, type?: HopPayloadType }) {
		this.channelId = channel_id;
		this.amountToForward = amount_to_forward;
		this.outgoingCltvValue = outgoing_cltv_value;
		this.type = type;
	}

	get size(): number {
		if (this.type === HopPayloadType.Legacy) {
			return 32;
		}

		const dataBuffer = this.toDataBuffer();
		return dataBuffer.length;
	}

	get sphinxSize(): number {
		if (this.type === HopPayloadType.Legacy) {
			return 33;
		}

		const payloadLength = this.size;
		const varint = new VarInt(payloadLength);
		return varint.length + payloadLength;
	}

	toDataBuffer(): Buffer {
		if (this.type !== HopPayloadType.Legacy) {
			// create sub-TLV packets
			const tu64Handler = new TypeHandler.tu64();
			const tu32Handler = new TypeHandler.tu32();

			// AMOUNT_TO_FORWARD: tu64
			const amountToForwardBuffer = tu64Handler.toBuffer(BigInt(this.amountToForward.toHex()));
			const amountToForwardTlv = new TLV(HopPayloadTLVTypes.AMOUNT_TO_FORWARD, amountToForwardBuffer);

			// OUTGOING_CLTV_VALUE: tu32
			const outgoingCltvValueBuffer = tu32Handler.toBuffer(this.outgoingCltvValue);
			const outgoingCltvValueTlv = new TLV(HopPayloadTLVTypes.OUTGOING_CLTV_VALUE, outgoingCltvValueBuffer);

			// SHORT_CHANNEL_ID: Buffer
			const channelIdTlv = new TLV(HopPayloadTLVTypes.SHORT_CHANNEL_ID, this.channelId);

			return Buffer.concat([amountToForwardTlv.toBuffer(), outgoingCltvValueTlv.toBuffer(), channelIdTlv.toBuffer()]);
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
			const varint = new VarInt(this.size);
			return Buffer.concat([varint.toBuffer(), dataBuffer]);
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
