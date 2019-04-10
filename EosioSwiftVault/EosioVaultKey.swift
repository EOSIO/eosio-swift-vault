//
//  EosioVaultKey.swift
//  EosioVault
//
//  Created by Todd Bowden on 8/26/18.
//  Copyright (c) 2018-2019 block.one
//

import Foundation
import EosioSwiftEcc

public extension EosioVault {
    
    public struct VaultKey {
        private (set) public var eosioPublicKey: String
        private (set) public var label: String?
        private (set) public var tag: String?
        private (set) public var curve: EllipticCurveType
        private (set) public var accessGroup: String
        private (set) public var isSecureEnclave: Bool
        private (set) public var bioFactor: EosioVault.BioFactor
        private (set) public var privateSecKey: SecKey?
        private (set) public var publicSecKey: SecKey?
        private (set) public var uncompressedPublicKey: Data?
        private (set) public var compressedPublicKey: Data?
        private (set) public var isRetired: Bool
        public var metadata: [String:Any]
        
        
        init?(eosioPublicKey: String? = nil, ecKey: Keychain.ECKey?, metadata: [String:Any]?) {
           
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
                self.metadata = metadata ?? [String:Any]()
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
                if tag.contains(words: EosioVault.BioFactor.fixed.rawValue) {
                    bioFactor = .fixed
                } else if tag.contains(words: EosioVault.BioFactor.flex.rawValue) {
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
            self.metadata = metadata ?? [String:Any]()
            
        }
    }
}
    
    
    
    

