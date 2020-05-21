//
//  Keychain.swift
//  EosioSwiftVault

//  Created by Todd Bowden on 8/13/18.
//  Copyright (c) 2017-2019 block.one and its contributors. All rights reserved.
//

import Foundation
import EosioSwift

public extension Keychain {

    /// ECKey collects properties into a single object for an elliptic curve key.
    class ECKey {
        /// The label for this key in the Keychain.
        private (set) public var label: String?
        /// The tag for this key in the Keychain.
        private (set) public var tag: String?
        /// The access group for this key in the Keychain.
        private (set) public var accessGroup: String
        /// Is the private key stored in the Secure Enclave?
        private (set) public var isSecureEnclave: Bool
        /// The private SecKey.
        private (set) public var privateSecKey: SecKey
        /// The public SecKey.
        private (set) public var publicSecKey: SecKey
        /// The uncompressed public key in ANSI X9.63 format (65 bytes, starts with 04).
        private (set) public var uncompressedPublicKey: Data
        /// The compressed public key in ANSI X9.63 format (33 bytes, starts with 02 or 03).
        private (set) public var compressedPublicKey: Data

        static func new(attributes: [String: Any]) throws -> ECKey {
            if let key = ECKey(attributes: attributes) {
                return key
            }
            guard let privkey = attributes[kSecValueRef as String] else {
                throw EosioError(.keyManagementError, reason: "Cannot get private key reference.")
            }
            let privateSecKey = privkey as! SecKey // swiftlint:disable:this force_cast
            guard let pubKey = SecKeyCopyPublicKey(privateSecKey) else {
                throw EosioError(.keyManagementError, reason: "Cannot get public key from private key.")
            }
            let publicSecKey = pubKey
            guard let ucpk = publicSecKey.externalRepresentation else {
                throw EosioError(.keyManagementError, reason: "Cannot get public key external representation.")
            }
            let uncompressedPublicKey = ucpk
            guard uncompressedPublicKey.compressedPublicKey != nil else {
                throw EosioError(.keyManagementError, reason: "Cannot get compressed public key.")
            }
            throw EosioError(.keyManagementError, reason: "Cannot create key")
        }

        /// Init an ECKey.
        ///
        /// - Parameter attributes: A dictionary of attributes from a Keychain query.
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
