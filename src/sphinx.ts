import chacha = require('chacha20');
import debugModule = require('debug');
import * as crypto from 'crypto';
import HopPayload from './hop_payload';
import SharedSecret, {KeyType} from './shared_secret';

const debug = debugModule('bolt04:sphinx');

export default class Sphinx {

	static readonly HMAC_LENGTH = 32;
	static readonly ONION_PACKET_LENGTH = 1300;

	private static generateFiller({sharedSecrets, payloads}: { sharedSecrets: Buffer[], payloads: HopPayload[] }) {
		const payloadSizes = payloads.map(p => p.sphinxSize + Sphinx.HMAC_LENGTH);
		const totalPayloadSize = payloadSizes.reduce((a, b) => a + b);
		const lastPayloadSize = payloadSizes[payloadSizes.length - 1];

		const fillerSize = totalPayloadSize - lastPayloadSize;
		const filler = Buffer.alloc(fillerSize, 0);

		let trailingPayloadSize = 0;
		for (let i = 0; i < sharedSecrets.length - 1; i++) {
			debug('Filler round %d', i);
			const currentSharedSecret = sharedSecrets[i];
			const currentPayloadSize = payloadSizes[i];

			debug('Shared secret: %s', currentSharedSecret.toString('hex'));
			const streamKey = SharedSecret.deriveKey({sharedSecret: currentSharedSecret, keyType: KeyType.Rho});
			debug('Stream key: %s', streamKey.toString('hex'));

			const fillerSourceStart = Sphinx.ONION_PACKET_LENGTH - trailingPayloadSize;
			const fillerSourceEnd = Sphinx.ONION_PACKET_LENGTH + currentPayloadSize;

			const streamLength = Sphinx.ONION_PACKET_LENGTH * 2;
			const streamBytes = chacha.encrypt(streamKey, Buffer.alloc(8, 0), Buffer.alloc(streamLength, 0));
			for (let j = fillerSourceStart; j < fillerSourceEnd; j++) {
				const fillerIndex = j - fillerSourceStart;
				const fillerValue = filler[fillerIndex];
				const streamValue = streamBytes[j];
				filler.writeUInt8(fillerValue ^ streamValue, fillerIndex);
			}

			trailingPayloadSize += currentPayloadSize;
		}

		return filler;
	}

	public static constructOnion({sharedSecrets, payloads, firstHopPublicKey, associatedData}: { sharedSecrets: Buffer[], payloads: HopPayload[], firstHopPublicKey: Buffer, associatedData?: Buffer }): Buffer {
		// generate the packet
		let nextHmac = Buffer.alloc(Sphinx.HMAC_LENGTH, 0); // the final hmac will be 0 bytes
		const filler = Sphinx.generateFiller({sharedSecrets, payloads});
		debug('Filler: %s', filler.toString('hex'));
		const onionPacket = Buffer.alloc(Sphinx.ONION_PACKET_LENGTH, 0);

		for (let i = sharedSecrets.length - 1; i >= 0; i--) {
			debug('Onion round %d', i);
			const currentSharedSecret = sharedSecrets[i];
			const currentPayload = payloads[i];
			const rhoKey = SharedSecret.deriveKey({sharedSecret: currentSharedSecret, keyType: KeyType.Rho});
			const muKey = SharedSecret.deriveKey({sharedSecret: currentSharedSecret, keyType: KeyType.Mu});

			// varuint encoding of the payload + fixed-width hmac
			const shiftSize = currentPayload.sphinxSize + Sphinx.HMAC_LENGTH;
			// right-shift onion packet bytes
			onionPacket.copyWithin(shiftSize, 0);
			const currentHopData = Buffer.concat([currentPayload.toSphinxBuffer(), nextHmac]);

			currentHopData.copy(onionPacket);

			const streamBytes = chacha.encrypt(rhoKey, Buffer.alloc(8, 0), Buffer.alloc(Sphinx.ONION_PACKET_LENGTH, 0));
			debug('Stream Bytes: %s', streamBytes.toString('hex'));
			debug('Hop data: %s', currentHopData.toString('hex'));

			// XOR the onion packet with the stream bytes
			for (let j = 0; j < 1300; j++) {
				// let's not XOR anything for now
				onionPacket.writeUInt8(onionPacket[j] ^ streamBytes[j], j);
			}

			if (i == sharedSecrets.length - 1) {
				filler.copy(onionPacket, onionPacket.length - filler.length);
			}

			debug('Raw onion: %s', onionPacket.toString('hex'));

			const nextHmacBuilder = crypto.createHmac('sha256', muKey).update(onionPacket);
			if (associatedData) {
				nextHmacBuilder.update(associatedData);
			}
			nextHmac = nextHmacBuilder.digest();
		}

		return Buffer.concat([Buffer.alloc(1, 0), firstHopPublicKey, onionPacket, nextHmac]);
	}

}
