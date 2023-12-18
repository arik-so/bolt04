import * as bigintBuffer from "bigint-buffer";
import {BigSize, TLV, TypeHandler} from 'lightning-tlv';

export enum HopPayloadType {
	Legacy,
	TLV
}

enum HopPayloadTLVTypes {
	AMOUNT_TO_FORWARD = 2,
	OUTGOING_CLTV_VALUE = 4,
	SHORT_CHANNEL_ID = 6
}

export default class HopPayload {
	private type: HopPayloadType;
	public readonly channelId?: Buffer | null;
	public readonly amountToForward: bigint;
	public readonly outgoingCltvValue: number;

	constructor({channel_id = null, amount_to_forward = 0, outgoing_cltv_value = 0, type = HopPayloadType.Legacy}: {
		channel_id?: Buffer | null,
		amount_to_forward?: bigint | number,
		outgoing_cltv_value?: number,
		type?: HopPayloadType
	}) {
		if (!!channel_id && channel_id.length !== 8) {
			throw new Error('channel_id must be 8 bytes');
		}
		this.channelId = channel_id;
		this.amountToForward = BigInt(amount_to_forward);
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
		const varint = new BigSize(payloadLength);
		return varint.length + payloadLength;
	}

	toDataBuffer(): Buffer {
		if (this.type !== HopPayloadType.Legacy) {
			// create sub-TLV packets
			const tu64Handler = new TypeHandler.tu64();
			const tu32Handler = new TypeHandler.tu32();

			// AMOUNT_TO_FORWARD: tu64
			const amountToForwardBuffer = tu64Handler.toBuffer(this.amountToForward);
			const amountToForwardTlv = new TLV(HopPayloadTLVTypes.AMOUNT_TO_FORWARD, amountToForwardBuffer);

			// OUTGOING_CLTV_VALUE: tu32
			const outgoingCltvValueBuffer = tu32Handler.toBuffer(this.outgoingCltvValue);
			const outgoingCltvValueTlv = new TLV(HopPayloadTLVTypes.OUTGOING_CLTV_VALUE, outgoingCltvValueBuffer);

			// SHORT_CHANNEL_ID: Buffer
			let channelIdTlvBuffer = Buffer.alloc(0);
			if (!!this.channelId && this.channelId.length > 0) {
				const channelIdTlv = new TLV(HopPayloadTLVTypes.SHORT_CHANNEL_ID, this.channelId);
				channelIdTlvBuffer = channelIdTlv.toBuffer();
			}

			return Buffer.concat([amountToForwardTlv.toBuffer(), outgoingCltvValueTlv.toBuffer(), channelIdTlvBuffer]);
		}
		const buffer = Buffer.alloc(32);

		if (!!this.channelId && this.channelId instanceof Buffer) {
			this.channelId.copy(buffer, 0);
		}

		const amountToForwardBuffer: Buffer = bigintBuffer.toBufferBE(this.amountToForward, 8);
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
			const varint = new BigSize(this.size);
			return Buffer.concat([varint.toBuffer(), dataBuffer]);
		}

		return Buffer.concat([Buffer.alloc(1, 0), dataBuffer]);
	}

	/**
	 *
	 * @param undelimitedHopPayloads
	 */
	static parseSphinxBuffer(undelimitedHopPayloads: Buffer): HopPayload {
		const firstByte = undelimitedHopPayloads[0];
		if (firstByte === 0) {
			// this is a legacy
			const sphinxBuffer = undelimitedHopPayloads.slice(0, 33);
			const dataBuffer = sphinxBuffer.slice(1);
			const channelId = dataBuffer.slice(0, 8);
			const amountToForward = bigintBuffer.toBigIntBE(dataBuffer.slice(8, 16));
			const outgoingCltvValue = dataBuffer.readUInt32BE(16);
			return new HopPayload({
				type: HopPayloadType.Legacy,
				channel_id: channelId,
				amount_to_forward: amountToForward,
				outgoing_cltv_value: outgoingCltvValue
			});
		} else {
			const bigSize = BigSize.parse(undelimitedHopPayloads);
			const dataLength = Number(bigSize.value);
			const lengthEncodingLength = bigSize.length;

			let remainingStream = undelimitedHopPayloads.slice(lengthEncodingLength, lengthEncodingLength + dataLength);

			const tlvs: TLV[] = [];
			while (remainingStream.length > 0) {
				const currentTlv = TLV.parse(remainingStream);
				remainingStream = remainingStream.slice(currentTlv.tlvSize);
				tlvs.push(currentTlv);
			}

			const hopPayloadConfig: any = {
				type: HopPayloadType.TLV
			};

			for (const currentTlv of tlvs) {
				const currentType = Number(currentTlv.type);
				if (currentType === HopPayloadTLVTypes.AMOUNT_TO_FORWARD) {
					const tu64Handler = new TypeHandler.tu64();
					hopPayloadConfig['amount_to_forward'] = tu64Handler.fromBuffer(currentTlv.value);
				} else if (currentType === HopPayloadTLVTypes.OUTGOING_CLTV_VALUE) {
					const tu32Handler = new TypeHandler.tu32();
					hopPayloadConfig['outgoing_cltv_value'] = tu32Handler.fromBuffer(currentTlv.value);
				} else if (currentType === HopPayloadTLVTypes.SHORT_CHANNEL_ID) {
					hopPayloadConfig['channel_id'] = currentTlv.value;
				}
			}

			return new HopPayload(hopPayloadConfig);
		}
	}
}
