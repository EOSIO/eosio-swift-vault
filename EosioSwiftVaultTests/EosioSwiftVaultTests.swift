//
//  EosioSwiftVaultTests.swift
//  EosioSwiftVaultTests
//
//  Created by Todd Bowden on 3/22/19.
//  Copyright (c) 2017-2019 block.one and its contributors. All rights reserved.
//

import XCTest
@testable import EosioSwiftVault

class EosioSwiftVaultTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
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

            guard let uncompressedPubKey2 = try? keychain.uncompressedR1PublicKey(data: compressedPubKey) else {
                return XCTFail("uncompression error")
            }
            XCTAssertEqual(uncompressedPubKey, uncompressedPubKey2)
         }
    }
}
