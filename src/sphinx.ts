import chacha = require('chacha20');
import debugModule = require('debug');
import * as crypto from 'crypto';
import HopPayload from './hop_payload';
import SharedSecret, {KeyType} from './shared_secret';

const debug = debugModule('bolt04:sphinx');

export default class Sphinx {

	static readonly HMAC_LENGTH = 32;
	static readonly ONION_PACKET_LENGTH = 1300;

	private version: number;
	private hopPayloads: Buffer;
	private ephemeralPublicKey: Buffer;
	private nextHmac: Buffer;

	private constructor({version = 0, rawOnion, ephemeralPublicKey, nextHmac}: { version?: number, rawOnion: Buffer, ephemeralPublicKey: Buffer, nextHmac: Buffer }) {
		this.version = version;
		this.hopPayloads = rawOnion;
		this.ephemeralPublicKey = ephemeralPublicKey;
		this.nextHmac = nextHmac;
	}

	public toBuffer() {
		return Buffer.concat([Buffer.alloc(1, this.version), this.ephemeralPublicKey, this.hopPayloads, this.nextHmac]);
	}

	public peel({sharedSecret, hopPrivateKey, associatedData}: { sharedSecret?: Buffer, hopPrivateKey?: Buffer, associatedData?: Buffer }): {
		hopPayload: HopPayload,
		sphinx?: Sphinx
	} {
		if (!!sharedSecret === !!hopPrivateKey) {
			throw new Error('sharedSecret XOR hopPrivateKey must be specified');
		}

		if (hopPrivateKey) {
			sharedSecret = SharedSecret.calculateSharedSecret({
				privateKey: hopPrivateKey,
				publicKey: this.ephemeralPublicKey
			});
		}

		debug('Shared secret: %s', sharedSecret.toString('hex'));

		const rhoKey = SharedSecret.deriveKey({sharedSecret: sharedSecret, keyType: KeyType.Rho});
		const muKey = SharedSecret.deriveKey({sharedSecret: sharedSecret, keyType: KeyType.Mu});
		debug('Rho key: %s', rhoKey.toString('hex'));
		debug('Mu key:  %s', muKey.toString('hex'));

		const currentHmacBuilder = crypto.createHmac('sha256', muKey).update(this.hopPayloads);
		if (associatedData) {
			currentHmacBuilder.update(associatedData);
		}
		const currentHmac = currentHmacBuilder.digest();

		debug('Expected HMAC: %s', this.nextHmac.toString('hex'));
		debug('Actual HMAC:   %s', currentHmac.toString('hex'));

		if (!currentHmac.equals(this.nextHmac)) {
			throw new Error('HMAC mismatch on peel');
		}

		const extendedPayload = Buffer.concat([this.hopPayloads, Buffer.alloc(Sphinx.ONION_PACKET_LENGTH, 0)]);
		const streamLength = Sphinx.ONION_PACKET_LENGTH * 2;
		const streamBytes = chacha.encrypt(rhoKey, Buffer.alloc(8, 0), Buffer.alloc(streamLength, 0));

		// apply the XOR
		for (let i = 0; i < extendedPayload.length; i++) {
			extendedPayload.writeUInt8(extendedPayload[i] ^ streamBytes[i], i);
		}

		const hopPayload = HopPayload.fromSphinxBuffer(extendedPayload);
		const hmacIndex = hopPayload.sphinxSize;
		const nextPayloadIndex = hmacIndex + Sphinx.HMAC_LENGTH;

		let nextSphinx = null;
		const nextHmac = extendedPayload.slice(hmacIndex, nextPayloadIndex);
		if (!nextHmac.equals(Buffer.alloc(Sphinx.HMAC_LENGTH, 0))) {
			const nextPayload = extendedPayload.slice(nextPayloadIndex, nextPayloadIndex + Sphinx.ONION_PACKET_LENGTH);
			const nextEphemeralPublicKey = SharedSecret.calculateNextEphemeralPublicKey({
				sharedSecret,
				ephemeralPublicKey: this.ephemeralPublicKey
			});
			nextSphinx = new Sphinx({
				version: this.version,
				ephemeralPublicKey: nextEphemeralPublicKey,
				rawOnion: nextPayload,
				nextHmac
			});
		}

		return {
			hopPayload,
			sphinx: nextSphinx
		};
	}

	public static fromBuffer(onion: Buffer) {
		const version = onion.readUInt8(0);
		const publicKey = onion.slice(1, 34);
		const nextHmac = onion.slice(-32);
		const rawOnion = onion.slice(34, -32);
		return new Sphinx({version, rawOnion, nextHmac, ephemeralPublicKey: publicKey});
	}

	public static constructOnion({sharedSecrets, payloads, firstHopPublicKey, associatedData}: { sharedSecrets: Buffer[], payloads: HopPayload[], firstHopPublicKey: Buffer, associatedData?: Buffer }): Sphinx {
		// generate the packet
		let nextHmac = Buffer.alloc(Sphinx.HMAC_LENGTH, 0); // the final hmac will be 0 bytes
		const filler = Sphinx.generateFiller({sharedSecrets, payloads});
		debug('Filler: %s', filler.toString('hex'));
		const hopPayloads = Buffer.alloc(Sphinx.ONION_PACKET_LENGTH, 0);

		for (let i = sharedSecrets.length - 1; i >= 0; i--) {
			debug('Onion round %d', i);
			const currentSharedSecret = sharedSecrets[i];
			const currentPayload = payloads[i];
			const rhoKey = SharedSecret.deriveKey({sharedSecret: currentSharedSecret, keyType: KeyType.Rho});
			const muKey = SharedSecret.deriveKey({sharedSecret: currentSharedSecret, keyType: KeyType.Mu});

			// varuint encoding of the payload + fixed-width hmac
			const shiftSize = currentPayload.sphinxSize + Sphinx.HMAC_LENGTH;
			// right-shift onion packet bytes
			hopPayloads.copyWithin(shiftSize, 0);
			const currentHopData = Buffer.concat([currentPayload.toSphinxBuffer(), nextHmac]);

			currentHopData.copy(hopPayloads);

			const streamBytes = chacha.encrypt(rhoKey, Buffer.alloc(8, 0), Buffer.alloc(Sphinx.ONION_PACKET_LENGTH, 0));
			debug('Stream Bytes: %s', streamBytes.toString('hex'));
			debug('Hop data: %s', currentHopData.toString('hex'));

			// XOR the onion packet with the stream bytes
			for (let j = 0; j < 1300; j++) {
				// let's not XOR anything for now
				hopPayloads.writeUInt8(hopPayloads[j] ^ streamBytes[j], j);
			}

			if (i == sharedSecrets.length - 1) {
				filler.copy(hopPayloads, hopPayloads.length - filler.length);
			}

			debug('Raw onion: %s', hopPayloads.toString('hex'));

			const nextHmacBuilder = crypto.createHmac('sha256', muKey).update(hopPayloads);
			if (associatedData) {
				nextHmacBuilder.update(associatedData);
			}
			nextHmac = nextHmacBuilder.digest();
		}

		return new Sphinx({rawOnion: hopPayloads, nextHmac, ephemeralPublicKey: firstHopPublicKey});
	}

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

}
