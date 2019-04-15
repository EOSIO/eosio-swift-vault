//
//  Keychain.swift
//  EosioSwiftVault

//  Created by Todd Bowden on 8/13/18.
//  Copyright (c) 2018-2019 block.one
//

import Foundation

public extension Keychain {

    class ECKey {
        private (set) public var label: String?
        private (set) public var tag: String?
        private (set) public var accessGroup: String
        private (set) public var isSecureEnclave: Bool
        private (set) public var privateSecKey: SecKey
        private (set) public var publicSecKey: SecKey
        private (set) public var uncompressedPublicKey: Data
        private (set) public var compressedPublicKey: Data

        public init?(attributes: [String: Any]) {
            label = attributes[kSecAttrLabel as String] as? String
            tag = attributes[kSecAttrApplicationTag as String] as? String
            accessGroup = attributes[kSecAttrAccessGroup as String] as? String ?? ""
            let tokenID = attributes[kSecAttrTokenID as String] as? String ?? ""
            isSecureEnclave = tokenID == kSecAttrTokenIDSecureEnclave as String
            guard let privkey = attributes[kSecValueRef as String] else {
                return nil
            }
            privateSecKey = privkey as! SecKey // swiftlint:disable:this force_cast
            guard let pubKey = SecKeyCopyPublicKey(privateSecKey) else {
                return nil
            }
            publicSecKey = pubKey
            guard let ucpk = publicSecKey.externalRepresentation else {
                return nil
            }
            uncompressedPublicKey = ucpk
            guard let cpk = uncompressedPublicKey.compressedPublicKey else {
                return nil
            }
            compressedPublicKey = cpk
        }
    }
}
