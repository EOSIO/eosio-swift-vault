//
//  EosioVaultKey.swift
//  EosioVault
//
//  Created by Todd Bowden on 8/26/18.
//  Copyright (c) 2017-2019 block.one and its contributors. All rights reserved.
//

import Foundation
#if SWIFT_PACKAGE
import EosioSwiftEcc
#else
import EosioSwift
#endif

public extension EosioVault {

    /// VaultKey collects properties into a single object for an EOSIO elliptic curve key.
    struct VaultKey {
        /// The EOSIO public key.
        private (set) public var eosioPublicKey: String
        /// The EOSIO private key. (nil for Secure Enclave keys).
        public var eosioPrivateKey: String? {
            guard let privateKey = privateKey else { return nil }
            guard privateKey.count >= 32 else { return nil }
            let pk32 = privateKey.suffix(32)
            switch curve {
            case .k1: return pk32.toEosioK1PrivateKey
            case .r1: return pk32.toEosioR1PrivateKey
            }
        }
        /// The label for this key in the Keychain.
        private (set) public var label: String?
        /// The tag for this key in the Keychain.
        private (set) public var tag: String?
        /// The curve for this key (r1 or k1).
        private (set) public var curve: EllipticCurveType
        /// The access group for this key in the Keychain.
        private (set) public var accessGroup: String
        /// Is the private key stored in the Secure Enclave?
        private (set) public var isSecureEnclave: Bool
        /// The biometric factor enforced on this key by the Keychain.
        private (set) public var bioFactor: BioFactor
        /// The private SecKey.
        private (set) public var privateSecKey: SecKey?
        /// The private key in ANSI X9.63 format. (nil for Secure Enclave keys).
        public var privateKey: Data? {
            return privateSecKey?.externalRepresentation
        }
        /// The public SecKey.
        private (set) public var publicSecKey: SecKey?
        /// The uncompressed public key in ANSI X9.63 format (65 bytes, starts with 04).
        private (set) public var uncompressedPublicKey: Data?
        /// The compressed public key in ANSI X9.63 format (33 bytes, starts with 02 or 03).
        private (set) public var compressedPublicKey: Data?
        /// Is the key retired? Retired keys have metadata without a key in the Keychain.
        private (set) public var isRetired: Bool
        /// Metadata for this key.
        /// - Important: Metadata must follow the rules for JSONSerialization.
        /// - SeeAlso: https://developer.apple.com/documentation/foundation/jsonserialization
        public var metadata: [String: Any]

        /// Init a VaultKey.
        ///
        /// - Parameters:
        ///   - eosioPublicKey: An EOSIO public key.
        ///   - ecKey: An ECKey.
        ///   - metadata: Metadata dictionary.
        /// - Important: Metadata must follow the rules for JSONSerialization.
        /// - SeeAlso: https://developer.apple.com/documentation/foundation/jsonserialization
        init?(eosioPublicKey: String? = nil, ecKey: Keychain.ECKey?, metadata: [String: Any]?) {

            // Case of publicKey + metadata with no ecKey = retired key
            guard let ecKey = ecKey else {
                guard let eosioPublicKey = eosioPublicKey else { return nil }
                self.eosioPublicKey = eosioPublicKey
                let version = (try? self.eosioPublicKey.eosioComponents().version) ?? ""
                self.curve = (try? EllipticCurveType(version)) ?? .r1
                self.bioFactor = .none
                self.accessGroup = ""
                self.isSecureEnclave = false
                self.isRetired = true
                self.metadata = metadata ?? [String: Any]()
                return
            }

            // Case with defined ecKey
            self.isSecureEnclave = ecKey.isSecureEnclave
            if isSecureEnclave {
                curve = .r1
            } else if let tag = ecKey.tag, tag.contains(words: EllipticCurveType.k1.rawValue) {
                curve = .k1
            } else {
                curve = .r1
            }

            guard let pubKey = try? ecKey.compressedPublicKey.toEosioPublicKey(curve: curve.rawValue) else { return nil }
            self.eosioPublicKey = pubKey

            // if eosioPublicKey defined, verify it matches the ecKey public key
            if let eosioPublicKey = eosioPublicKey {
                guard eosioPublicKey == self.eosioPublicKey else { return nil }
            }

            label = ecKey.label
            tag = ecKey.tag
            accessGroup = ecKey.accessGroup

            if let tag = self.tag {
                if tag.contains(words: BioFactor.fixed.rawValue) {
                    bioFactor = .fixed
                } else if tag.contains(words: BioFactor.flex.rawValue) {
                    bioFactor = .flex
                } else {
                    bioFactor = .none
                }
            } else {
                bioFactor = .none
            }

            isRetired = false
            privateSecKey = ecKey.privateSecKey
            publicSecKey = ecKey.publicSecKey
            uncompressedPublicKey = ecKey.uncompressedPublicKey
            compressedPublicKey = ecKey.compressedPublicKey
            self.metadata = metadata ?? [String: Any]()

        }
    }
}
