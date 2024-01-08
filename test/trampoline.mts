import chai from 'chai';
import {default as Bigi} from 'bigi';
import HopPayload, {HopPayloadTLVTypes, HopPayloadType} from '../src/hop_payload.mjs';
import Sphinx from '../src/sphinx.mjs';
import {TLV, TypeHandler} from "lightning-tlv";
import ecurve, {Point} from 'ecurve';
import SharedSecret from '../src/shared_secret.mjs';
const secp256k1 = ecurve.getCurveByName('secp256k1');

const assert = chai.assert;

describe('Sphinx Tests', () => {

	it('should construct a Trampoline onion packet', () => {
		const firstPublicKey = Buffer.from('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619', 'hex');
		const associatedData = Buffer.from('4242424242424242424242424242424242424242424242424242424242424242', 'hex');
		const sharedSecrets = [
			Buffer.from('53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66', 'hex'),
			Buffer.from('a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae', 'hex'),
			Buffer.from('3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc', 'hex'),
			Buffer.from('21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d', 'hex'),
			Buffer.from('b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328', 'hex')
		];

		const payloads = [];
		for (let i = 0; i < 5; i++) {
			const currentChannelId = Buffer.alloc(8, i);
			const currentPayload = new HopPayload({
				channel_id: currentChannelId,
				amount_to_forward: i,
				outgoing_cltv_value: i,
				type: HopPayloadType.TLV
			});
			if (i === 2) {
				const typeHandler = new TypeHandler.tu16();
				currentPayload.additionalTLVs = [
					new TLV(HopPayloadTLVTypes.TRAMPOLINE_ENTRY_NODE, Buffer.alloc(1, 1)),
					new TLV(HopPayloadTLVTypes.TRAMPOLINE_MAX_REWRAP_OFFSET, Buffer.alloc(1, typeHandler.toBuffer(650))),
				]
			}
			payloads.push(currentPayload);
		}

		const onion = Sphinx.constructOnion({
			sharedSecrets, payloads, associatedData, firstHopPublicKey: firstPublicKey
		}).toBuffer();
		assert.typeOf(onion, 'UInt8Array');
		assert.lengthOf(onion, 1366);
		assert.equal(onion.toString('hex'), '0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619ebf34354c2a167c232b5e46d421e966d2d545b3a1c28c04e6e42d64f7fa40051db701d5eede502b283e3c6d63e43d68ae7cacfaae40c69d1067246317b347907fb3f4aed2f649c41b1286b14595bd3b94c3b6f5577e6983e7518a7416747592386958628ec425b98cbc37e1da4aa40cec206ce525da0e178accad6ce4464cc6b4e160a53240fecf71b7517634aca1dd4267c5e7a02863c04e6442ef4c37c276df44376a25a1f5a2c7e2f7638f6445188bef7e78e942d7d92677a08fdbf12c05e650ba49bed990a900d90582c9b62a4b1d459384b0e0c338266e9fae9ecbc976e3aba747b15c88f6b182753c6a56c50230ed61f5c7817785a9a680b27310acc2c11a42029800b221804049ebffd5b93e1867409b2aa0a650c3af26d7b305f020bc27f0427a74d0a62bf12381c77c2b1694654a1e293d916612eab69f77f2b02aefac1d364b182489d2197814b644dd3be921dc752283ea73e9b2425d7223404ad0d66827e5e1b84badeb76dd5e5355d79cc7a6db787ad18b0d66ec0c3dc4e59623a86154ea6944026b917cd44b2fbef97d410d4fc1a9d3c4945e6dbcbddd990c6c46aeec3faa5def47cd5d370257da87e9ff66c1519957b46d270e17b96145e96403604cf3020a896f5d35cda699962b9f4c5597572c968cfca941705cccd25d477cf49cd0eff611efeb165e2e3f75d1c51e7d2fe43937fa2a2f4ab62bc00b86585b47d2702f2ae86e1969198441dcf722aae42aad5cf2eac3940ccc422e19a614d16eace2e1d0693b125ba9a17091c606018f579318d55ff9d65d18b5bdc84bf55eae300d6391940cc1dc0309aadd6dbf68214d9f137ff619e61fb9bf62d9516f2316f5e307529c99058dd713fafec9dbb2b3d428876d17ca9d89e73ce4696bf0709bd860627e9365cdace60a93fb5a6d7ac11d77a606cdd45f3568596ba8fff87c327340015a36b2b5f7195c4ba989ceb9c51f7cb9ae03c7a718d4f65c8565847429e31a1dbfcdcf71c88324dcc9858518307adf4b4f222d6f240aca1b959ef6af992817a7f8bbf4b9905144f36a0f0bcdf20c39341a43e5ae0368edce9cfab66d20a9c13cd2730dacfc4a1f6a1457441f6185b167a13cfbf81644b83c19db2c37be4cacc575248180ab435a99cac5f0fe6863c0be7f2f94e596d12252274edc3557e4f30559617f7144f9000285869b20f2617e7c991cd91071aa562b6cb5b8a2a163d47ab9c30d6eebda9794e3cac8e18b85fd2dd8c513912cdb5123096396abe837de30c2640d0c3ab1517cb072dc0e131f6b86f1d90f6c46d784064bd7f316997e50de7383f66836fe5c35e9429c69cf7de7ff4570fb39576f6cad75624d2d28dd7982c06912c5a753c034c1009500ed8cdcd0907a336f3a31aa181d39d87bf2f91b1fb8a91351a50e90fc11b1221bd6c3ce2062f3d04937fe0ab61eb5eb8104ff2c24bc3f975d73b59855391e1208363ab9a659265ab44963c247e571fa360b727b4f5fcff2b4d9cb76f01f5e8adbd80334d50f09f7180529a2a2c5ad60b82b02c5e91af3dd6640a273fb32ccf48e97999df58b6748ac27129179c83297a89d8f8081bcc2bece906a5a19ecad20ce7c46f62107dc1d6f14e67f6a77b33858726317fa2525ee6924a6d06e52b82965539d1dae745bb0409d56b4c2d7bdda90802864629f00204e788fc6fc188f9acea10b3f7b28c70f40212daa47027968ecdcfada29f2ed33f58eb3bbf8b63696ed538f436f496570933fc46aa3b3a0c06e095a6d057fdcbdd2e664baf3515913f97d0c5247c7ef206686147882e06ddaec6343a6c2293790712c084303c84392c9832e86de27318a4fe393eeec5f33ae406197ccbbf73e46baa58760c6efe6e2b547c11');

		const restoredSphinx = Sphinx.fromBuffer(onion);
		assert.equal(restoredSphinx.toBuffer().toString('hex'), onion.toString('hex'));
	});

	it('should rewrap a Trampoline onion packet', () => {
		const onion = Buffer.from('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619ebf34354c2a167c232b5e46d421e966d2d545b3a1c28c04e6e42d64f7fa40051db701d5eede502b283e3c6d63e43d68ae7cacfaae40c69d1067246317b347907fb3f4aed2f649c41b1286b14595bd3b94c3b6f5577e6983e7518a7416747592386958628ec425b98cbc37e1da4aa40cec206ce525da0e178accad6ce4464cc6b4e160a53240fecf71b7517634aca1dd4267c5e7a02863c04e6442ef4c37c276df44376a25a1f5a2c7e2f7638f6445188bef7e78e942d7d92677a08fdbf12c05e650ba49bed990a900d90582c9b62a4b1d459384b0e0c338266e9fae9ecbc976e3aba747b15c88f6b182753c6a56c50230ed61f5c7817785a9a680b27310acc2c11a42029800b221804049ebffd5b93e1867409b2aa0a650c3af26d7b305f020bc27f0427a74d0a62bf12381c77c2b1694654a1e293d916612eab69f77f2b02aefac1d364b182489d2197814b644dd3be921dc752283ea73e9b2425d7223404ad0d66827e5e1b84badeb76dd5e5355d79cc7a6db787ad18b0d66ec0c3dc4e59623a86154ea6944026b917cd44b2fbef97d410d4fc1a9d3c4945e6dbcbddd990c6c46aeec3faa5def47cd5d370257da87e9ff66c1519957b46d270e17b96145e96403604cf3020a896f5d35cda699962b9f4c5597572c968cfca941705cccd25d477cf49cd0eff611efeb165e2e3f75d1c51e7d2fe43937fa2a2f4ab62bc00b86585b47d2702f2ae86e1969198441dcf722aae42aad5cf2eac3940ccc422e19a614d16eace2e1d0693b125ba9a17091c606018f579318d55ff9d65d18b5bdc84bf55eae300d6391940cc1dc0309aadd6dbf68214d9f137ff619e61fb9bf62d9516f2316f5e307529c99058dd713fafec9dbb2b3d428876d17ca9d89e73ce4696bf0709bd860627e9365cdace60a93fb5a6d7ac11d77a606cdd45f3568596ba8fff87c327340015a36b2b5f7195c4ba989ceb9c51f7cb9ae03c7a718d4f65c8565847429e31a1dbfcdcf71c88324dcc9858518307adf4b4f222d6f240aca1b959ef6af992817a7f8bbf4b9905144f36a0f0bcdf20c39341a43e5ae0368edce9cfab66d20a9c13cd2730dacfc4a1f6a1457441f6185b167a13cfbf81644b83c19db2c37be4cacc575248180ab435a99cac5f0fe6863c0be7f2f94e596d12252274edc3557e4f30559617f7144f9000285869b20f2617e7c991cd91071aa562b6cb5b8a2a163d47ab9c30d6eebda9794e3cac8e18b85fd2dd8c513912cdb5123096396abe837de30c2640d0c3ab1517cb072dc0e131f6b86f1d90f6c46d784064bd7f316997e50de7383f66836fe5c35e9429c69cf7de7ff4570fb39576f6cad75624d2d28dd7982c06912c5a753c034c1009500ed8cdcd0907a336f3a31aa181d39d87bf2f91b1fb8a91351a50e90fc11b1221bd6c3ce2062f3d04937fe0ab61eb5eb8104ff2c24bc3f975d73b59855391e1208363ab9a659265ab44963c247e571fa360b727b4f5fcff2b4d9cb76f01f5e8adbd80334d50f09f7180529a2a2c5ad60b82b02c5e91af3dd6640a273fb32ccf48e97999df58b6748ac27129179c83297a89d8f8081bcc2bece906a5a19ecad20ce7c46f62107dc1d6f14e67f6a77b33858726317fa2525ee6924a6d06e52b82965539d1dae745bb0409d56b4c2d7bdda90802864629f00204e788fc6fc188f9acea10b3f7b28c70f40212daa47027968ecdcfada29f2ed33f58eb3bbf8b63696ed538f436f496570933fc46aa3b3a0c06e095a6d057fdcbdd2e664baf3515913f97d0c5247c7ef206686147882e06ddaec6343a6c2293790712c084303c84392c9832e86de27318a4fe393eeec5f33ae406197ccbbf73e46baa58760c6efe6e2b547c11', 'hex');
		const sphinx = Sphinx.fromBuffer(onion);

		const associatedData = Buffer.from('4242424242424242424242424242424242424242424242424242424242424242', 'hex');

		const hopPrivateKeys = [
			Buffer.from('4141414141414141414141414141414141414141414141414141414141414141', 'hex'),
			Buffer.from('4242424242424242424242424242424242424242424242424242424242424242', 'hex'),
			Buffer.from('4343434343434343434343434343434343434343434343434343434343434343', 'hex'),
			Buffer.from('4444444444444444444444444444444444444444444444444444444444444444', 'hex'),
			Buffer.from('4545454545454545454545454545454545454545454545454545454545454545', 'hex')
		];

		const peel0 = sphinx.peel({hopPrivateKey: hopPrivateKeys[0]!, associatedData});
		const peel1 = peel0.sphinx!.peel({hopPrivateKey: hopPrivateKeys[1]!, associatedData});
		const peel2 = peel1.sphinx!.peel({
			sharedSecret: Buffer.from('3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc', 'hex'),
			associatedData
		});


		let expectedSharedSecret = Buffer.from('21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d', 'hex');


		// const peel3 = peel2.sphinx!.peel({sharedSecret: expectedSharedSecret, associatedData: associatedData});
		let peel3;


		const trampolineSessionPrivateKey = Buffer.from('6161616161616161616161616161616161616161616161616161616161616161', 'hex');
		const trampolineSessionPublicKey = secp256k1.G.multiply(Bigi.fromBuffer(trampolineSessionPrivateKey)).getEncoded(true);
		const trampolineHopPrivateKeys = [
			Buffer.from('5151515151515151515151515151515151515151515151515151515151515151', 'hex'),
			Buffer.from('5252525252525252525252525252525252525252525252525252525252525252', 'hex')
		];
		const trampolineHopPublicKeys = trampolineHopPrivateKeys.map(sk => secp256k1.G.multiply(Bigi.fromBuffer(sk)).getEncoded(true));
		const trampolineSharedSecrets = SharedSecret.calculateSharedSecrets({sessionKey: trampolineSessionPrivateKey, hopPublicKeys: trampolineHopPublicKeys});
		const trampolineAssociatedData = Buffer.from('6262626262626262626262626262626262626262626262626262626262626262', 'hex');
		const trampolineHopPayloads = [];
		{
			for (let i = 0; i < 2; i++) {
				const currentChannelId = Buffer.alloc(8, i + 10);
				const currentPayload = new HopPayload({
					channel_id: currentChannelId,
					amount_to_forward: i,
					outgoing_cltv_value: i,
					type: HopPayloadType.TLV
				});
				if (i === 1) {
					const typeHandler = new TypeHandler.tu16();
					currentPayload.additionalTLVs = [
						// new TLV(HopPayloadTLVTypes.TRAMPOLINE_ENTRY_NODE, Buffer.alloc(1, 1)),
						new TLV(HopPayloadTLVTypes.TRAMPOLINE_MAX_REWRAP_OFFSET, Buffer.alloc(1, typeHandler.toBuffer(650))),
						new TLV(HopPayloadTLVTypes.TRAMPOLINE_EXIT_KEY, peel2!.sphinx!.ephemeralPublicKey)
					]
				}
				trampolineHopPayloads.push(currentPayload);
			}
		}

		const trampolineWrappedOnion = Sphinx.wrapOnion({sharedSecrets: trampolineSharedSecrets, payloads: trampolineHopPayloads, firstHopPublicKey: trampolineSessionPublicKey, associatedData: trampolineAssociatedData}, peel2.sphinx!)
		const trampolineOnionBuffer = trampolineWrappedOnion.toBuffer();

		{
			const trampolineSphinx = Sphinx.fromBuffer(trampolineOnionBuffer);
			const tp1 = trampolineSphinx.peel({hopPrivateKey: trampolineHopPrivateKeys[0]!, associatedData: trampolineAssociatedData});
			const tp2 = tp1.sphinx!.peel({hopPrivateKey: trampolineHopPrivateKeys[1]!, associatedData: trampolineAssociatedData});

			// this should be the public key
			const nonTrampolineSessionEntryKey = tp2.hopPayload.additionalTLVs[1]!.value!;
			const nextSharedSecret = SharedSecret.calculateSharedSecret({publicKey: nonTrampolineSessionEntryKey, privateKey: hopPrivateKeys[3]!});
			console.log('Non-trampoline shared secret:', nextSharedSecret.toString('hex'));
			peel3 = peel2.sphinx!.peel({sharedSecret: expectedSharedSecret, associatedData: associatedData});
		}
		
		
		// peel2.hopPayload


		// const peel3 = peel2.sphinx!.peel({hopPrivateKey: hopPrivateKeys[3]!, associatedData});
		const peel4 = peel3.sphinx!.peel({hopPrivateKey: hopPrivateKeys[4]!, associatedData});
		assert.isNull(peel4.sphinx);

		const lastHopPayload = peel4.hopPayload;
		assert.instanceOf(lastHopPayload, HopPayload);
		assert.equal(lastHopPayload.outgoingCltvValue, 4);
	});

});
