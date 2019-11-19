import SharedSecret, {KeyType} from '../src/shared_secret';
import chai = require('chai');

const assert = chai.assert;

describe('Shared Secret Tests', () => {

	it('should calculate shared secrets', () => {
		const pubkeyHexes = [];
		pubkeyHexes[0] = '02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619';
		pubkeyHexes[1] = '0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c';
		pubkeyHexes[2] = '027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007';
		pubkeyHexes[3] = '032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991';
		pubkeyHexes[4] = '02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145';
		const pubkeys = pubkeyHexes.map(hex => Buffer.from(hex, 'hex'));

		const sessionKey = Buffer.from('4141414141414141414141414141414141414141414141414141414141414141', 'hex');

		const sharedSecrets = SharedSecret.calculateSharedSecrets({sessionKey, hopPublicKeys: pubkeys});
		assert.lengthOf(sharedSecrets, 5);
		assert.typeOf(sharedSecrets[0], 'UInt8Array');
		assert.equal(sharedSecrets[0].toString('hex'), '53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66');
		assert.equal(sharedSecrets[1].toString('hex'), 'a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae');
		assert.equal(sharedSecrets[2].toString('hex'), '3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc');
		assert.equal(sharedSecrets[3].toString('hex'), '21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d');
		assert.equal(sharedSecrets[4].toString('hex'), 'b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328');
	});

	it('should derive a key from shared secret', () => {
		const sharedSecret = Buffer.from('b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328', 'hex');
		const rhoKey = SharedSecret.deriveKey({sharedSecret, keyType: KeyType.Rho});
		assert.typeOf(rhoKey, 'UInt8Array');
		assert.equal(rhoKey.toString('hex'), '034e18b8cc718e8af6339106e706c52d8df89e2b1f7e9142d996acf88df8799b');
	});

});
