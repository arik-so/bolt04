import Bigi = require('bigi');
import debugModule = require('debug');
import ecurve = require('ecurve');
import * as crypto from 'crypto';

const debug = debugModule('bolt04:shared_secret');
const secp256k1 = ecurve.getCurveByName('secp256k1');

export default class SharedSecret {

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

			const blinding_factor_preimage = Buffer.concat([ephemeralPublicKey.getEncoded(true), ss_k]);
			const blinding_factor = crypto.createHash('sha256').update(blinding_factor_preimage).digest();
			debug('Blinding factor: %s', blinding_factor.toString('hex'));

			const blinding_factor_integer = Bigi.fromBuffer(blinding_factor);
			ephemeralPrivateKey = ephemeralPrivateKey.multiply(blinding_factor_integer).mod(secp256k1.n);
		}

		return hopSharedSecrets;
	}
}
