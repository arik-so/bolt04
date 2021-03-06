import Bigi = require('bigi');
import debugModule = require('debug');
import ecurve = require('ecurve');
import * as crypto from 'crypto';
import {Point} from 'ecurve';

const debug = debugModule('bolt04:shared_secret');
const secp256k1 = ecurve.getCurveByName('secp256k1');

export enum KeyType {
	Rho = 'rho',
	Mu = 'mu',
	Um = 'um'
}

export default class SharedSecret {

	public static calculateSharedSecret({privateKey, publicKey}: { privateKey: Buffer, publicKey: Buffer }): Buffer {
		const sharedSecrets = this.calculateSharedSecrets({sessionKey: privateKey, hopPublicKeys: [publicKey]});
		return sharedSecrets[0];
	}

	public static calculateSharedSecrets({sessionKey, hopPublicKeys}: { sessionKey: Buffer, hopPublicKeys: Buffer[] }): Buffer[] {
		let ephemeralPrivateKey = Bigi.fromBuffer(sessionKey);
		const hopSharedSecrets = [];

		for (let i = 0; i < hopPublicKeys.length; i++) {
			debug('Round %d', i);

			const hopPublicKey = ecurve.Point.decodeFrom(secp256k1, hopPublicKeys[i]);
			const ecdh = hopPublicKey.multiply(ephemeralPrivateKey).getEncoded(true);
			const ss_k = crypto.createHash('sha256').update(ecdh).digest();
			hopSharedSecrets.push(ss_k);
			debug('Shared secret: %s', ss_k.toString('hex'));

			if (i >= hopPublicKeys.length - 1) {
				break;
			}

			const ephemeralPublicKey = secp256k1.G.multiply(ephemeralPrivateKey);
			debug('Ephemeral private key: %s', ephemeralPrivateKey.toHex(32));
			debug('Ephemeral public key: %s', ephemeralPublicKey.getEncoded(true).toString('hex'));

			const blinding_factor_integer = this.calculateBlindingFactor({
				ephemeralPublicKey: ephemeralPublicKey,
				sharedSecret: ss_k
			});
			ephemeralPrivateKey = ephemeralPrivateKey.multiply(blinding_factor_integer).mod(secp256k1.n);
		}

		return hopSharedSecrets;
	}

	private static calculateBlindingFactor({ephemeralPublicKey, sharedSecret}: { ephemeralPublicKey: Point, sharedSecret: Buffer }): Bigi {
		const blinding_factor_preimage = Buffer.concat([ephemeralPublicKey.getEncoded(true), sharedSecret]);
		const blinding_factor = crypto.createHash('sha256').update(blinding_factor_preimage).digest();
		debug('Blinding factor: %s', blinding_factor.toString('hex'));

		return Bigi.fromBuffer(blinding_factor);
	}

	public static calculateNextEphemeralPublicKey({ephemeralPublicKey, sharedSecret}: { ephemeralPublicKey: Buffer, sharedSecret: Buffer }): Buffer {
		const publicKeyPoint: Point = ecurve.Point.decodeFrom(secp256k1, ephemeralPublicKey);
		const blindingFactor = this.calculateBlindingFactor({ephemeralPublicKey: publicKeyPoint, sharedSecret});
		const nextPublicKey = publicKeyPoint.multiply(blindingFactor);
		return nextPublicKey.getEncoded(true);
	}

	public static deriveKey({sharedSecret, keyType}: { sharedSecret: Buffer, keyType: KeyType }): Buffer {
		return crypto.createHmac('sha256', keyType).update(sharedSecret).digest();
	}
}
