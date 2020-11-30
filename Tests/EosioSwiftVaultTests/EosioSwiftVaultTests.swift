//
//  EosioSwiftVaultTests.swift
//  EosioSwiftVaultTests
//
//  Created by Todd Bowden on 3/22/19.
//  Copyright (c) 2017-2019 block.one and its contributors. All rights reserved.
//

import XCTest
import EosioSwiftEcc
@testable import EosioSwiftVault

class EosioSwiftVaultTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testCompressUncompressR1KeysRoundTrip() {
        let keychain = Keychain(accessGroup: "")
         for _ in 0...100 {
            let key = keychain.createEllipticCurvePrivateKey(isPermanent: false)
            guard let uncompressedPubKey = key?.publicKey?.externalRepresentation else {
                return XCTFail("Not a valid key")
            }

            guard let compressedPubKey = uncompressedPubKey.compressedPublicKey else {
                return XCTFail("Not a valid key")
            }

            guard let uncompressedPubKey2 = try? keychain.uncompressedPublicKey(data: compressedPubKey) else {
                return XCTFail("uncompression error")
            }
            XCTAssertEqual(uncompressedPubKey, uncompressedPubKey2)
         }
    }

    func generatePrivateKeyBytes() -> Data? {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { return nil }
        return Data(bytes)
    }

    func testCompressUncompressK1KeysRoundTrip() {
        let keychain = Keychain(accessGroup: "")
        do {
            for _ in 0...100 {
               guard let privKey = generatePrivateKeyBytes() else {
                   return XCTFail("Not a valid pk")
               }
               let uncompressedPubKey = try EccRecoverKey.recoverPublicKey(privateKey: privKey, curve: .k1)
               guard let compressedPubKey = uncompressedPubKey.compressedPublicKey else {
                   return XCTFail("Not a valid key")
               }
               guard let uncompressedPubKey2 = try? keychain.uncompressedPublicKey(data: compressedPubKey, curve: "K1") else {
                   return XCTFail("uncompression error")
               }
               XCTAssertEqual(uncompressedPubKey, uncompressedPubKey2)
            }
        } catch {
            return XCTFail(error.eosioError.reason)
        }

    }

}
