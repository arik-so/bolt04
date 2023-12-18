import HopPayload, {HopPayloadType} from '../src/hop_payload.mjs';
import chai from 'chai';

const assert = chai.assert;

describe('Hop Payload Test', () => {

	describe('Legacy serialization', () => {

		it('should serialize a hop payload', () => {
			const hopPayload = new HopPayload({
				amount_to_forward: 0.7e8, // half a bitcoin
				outgoing_cltv_value: 124,
				channel_id: Buffer.from([10, 11, 12, 13, 14, 15, 16, 17]),
				type: HopPayloadType.Legacy
			});

			const serialization = hopPayload.toSphinxBuffer();
			assert.equal(hopPayload.sphinxSize, serialization.length);
			assert.equal(hopPayload.sphinxSize, 33);
			assert.equal(serialization.toString('hex'), '000a0b0c0d0e0f101100000000042c1d800000007c000000000000000000000000');
		});

		it('should deserialize a hop payload', () => {
			const undelimitedBuffer = Buffer.from('000a0b0c0d0e0f101100000000042c1d800000007c000000000000000000000000', 'hex');
			const hopPayload = HopPayload.parseSphinxBuffer(undelimitedBuffer);
			assert.equal(hopPayload.channelId!.toString('hex'), '0a0b0c0d0e0f1011');
			assert.equal(hopPayload.amountToForward, BigInt(0.7e8));
			assert.equal(hopPayload.outgoingCltvValue, 124);
		});

	});

	describe('TLV serialization', () => {

		it('should serialize a hop payload', () => {
			const hopPayload = new HopPayload({
				amount_to_forward: 0.5e8, // half a bitcoin
				outgoing_cltv_value: 137,
				channel_id: null,
				type: HopPayloadType.TLV
			});

			const serialization = hopPayload.toSphinxBuffer();
			assert.equal(hopPayload.sphinxSize, serialization.length);
			assert.equal(serialization.toString('hex'), '09020402faf080040189');
		});

		it('should deserialize a hop payload', () => {
			const undelimitedBuffer = Buffer.from('09020402faf0800401899ab10fc8', 'hex');
			const hopPayload = HopPayload.parseSphinxBuffer(undelimitedBuffer);
			assert.isNull(hopPayload.channelId);
			assert.equal(hopPayload.amountToForward, BigInt(0.5e8));
			assert.equal(hopPayload.outgoingCltvValue, 137);
		});

		it('should deserialize an out-of-order hop payload', () => {
			const undelimitedBuffer = Buffer.from('09040189020402faf080', 'hex');
			const hopPayload = HopPayload.parseSphinxBuffer(undelimitedBuffer);
			assert.isNull(hopPayload.channelId);
			assert.equal(hopPayload.amountToForward, BigInt(0.5e8));
			assert.equal(hopPayload.outgoingCltvValue, 137);
		});

	});

});
