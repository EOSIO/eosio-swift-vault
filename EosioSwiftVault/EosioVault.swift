//
//  EosioVault.swift
//  EosioVault
//
//  Created by Todd Bowden on 6/4/18.
//

import Foundation
import LocalAuthentication
import EosioSwift
import EosioSwiftEcc

public final class EosioVault {
    
    public static let updateNotification = Notification.Name("EosioVaultUpdateNotification")
    
    var keychain: Keychain
    private let vaultTag = "__VAULT__"
    private let eosioKeyMetadataService = "EosioKeyMetadataService"
   
    public var accessGroup = "" {
        didSet {
            keychain = Keychain(accessGroup: accessGroup)
        }
    }
    
    public enum BioFactor: String {
        case none = ""
        case flex = "bio flex"
        case fixed = "bio fixed"
    }
    
    private var context:LAContext!
    

    /// Init with accessGroup. The accessGroup allows multiple apps (including extensions) in the same team to share the same keychain.
    public init(accessGroup: String) {
        keychain = Keychain(accessGroup: accessGroup)
    }
    
    
    func postUpdateNotification(eosioPublicKey: String, action: String) {
        NotificationCenter.default.post(name: EosioVault.updateNotification, object: nil, userInfo: ["eosioPublicKey":eosioPublicKey, "action":action])
    }
    
    
    /// Get VaultIdentifierKey
    /// (special secure enclave key with tag "__VAULT__" - create if not present)
    public func vaultIdentifierKey() throws -> Keychain.ECKey {
        var vaultKeyArray = try keychain.getAllEllipticCurveKeys(tag: vaultTag)
        
        if vaultKeyArray.count == 0 {
            let _ = try keychain.createSecureEnclaveSecKey(tag: vaultTag, label: nil, accessFlag: nil)
            vaultKeyArray = try keychain.getAllEllipticCurveKeys(tag: vaultTag)
        }
        guard let vaultIdentifierKey = vaultKeyArray.first else {
            throw EosioError(EosioErrorCode.keyManagementError, reason: "Unable to create vault key")
        }
        return vaultIdentifierKey
    }
    
    
    /// VaultIdentifier is the VaultIdentifierKey public key as hex
    public func vaultIdentifier() throws -> String {
        let key = try vaultIdentifierKey()
        return key.uncompressedPublicKey.hex
    }
    
    
    /// Create a new secure enclave key and return the Vault Key.
    public func newSecureEnclaveKey(bioFactor: BioFactor = .none, metadata: [String:Any]? = nil) throws -> EosioVault.VaultKey {
        var tag: String?
        var accessFlag: SecAccessControlCreateFlags?
        switch bioFactor {
        case .flex:
            accessFlag = .biometryAny
            tag = bioFactor.rawValue
        case .fixed:
            accessFlag = .biometryCurrentSet
            tag = bioFactor.rawValue
        case .none:
            accessFlag = nil
            tag = nil
        }
    
        let secKey = try keychain.createSecureEnclaveSecKey(tag: tag, label: nil, accessFlag: accessFlag)
        guard let eosioPublicKey = secKey.publicKey?.externalRepresentation?.compressedPublicKey?.toEosioR1PublicKey else {
            throw EosioError(.keyManagementError, reason: "Unable to create public key")
        }
        var vaultKey = try getVaultKey(eosioPublicKey: eosioPublicKey)
        if let metadata = metadata {
            vaultKey.metadata = metadata
            let _ = update(key: vaultKey)
        }
        postUpdateNotification(eosioPublicKey: eosioPublicKey, action: "new")
        return vaultKey
    }
    
    
    /// Add external eosio private key. Returns VaultKey or throws error.
    public func addExternal(eosioPrivateKey: String, metadata: [String:Any]? = nil) throws -> EosioVault.VaultKey {
        let eosioKeyComponents = try eosioPrivateKey.eosioComponents()
        let curve = try EllipticCurveType(eosioKeyComponents.version)
        let privateKeyData = try Data(eosioPrivateKey: eosioPrivateKey)
        let publicKeyData = try EccRecoverKey.recoverPublicKey(privateKey: privateKeyData, curve: curve)
        let ecKey = try keychain.importExternal(privateKey: publicKeyData + privateKeyData, tag: curve.rawValue)
        var vaultKey = try getVaultKey(eosioPublicKey: ecKey.compressedPublicKey.toEosioPublicKey(curve: curve.rawValue))
        if let metadata = metadata {
            vaultKey.metadata = metadata
            let _ = update(key: vaultKey)
        }
        postUpdateNotification(eosioPublicKey: vaultKey.eosioPublicKey, action: "new")
        return vaultKey
    }
    
    
    /// Delete a key given the public key. USE WITH CARE!
    public func deleteKey(eosioPublicKey: String) throws {
        let pubKeyData = try Data(eosioPublicKey: eosioPublicKey)
        keychain.deleteKey(publicKey: pubKeyData)
        deleteKeyMetadata(publicKey: eosioPublicKey)
    }
    
    
    /// Update label
    public func update(label: String, publicKey: String) throws {
        let pubKeyData = try Data(eosioPublicKey: publicKey)
        keychain.update(label: label, publicKey: pubKeyData)
    }
    

    /// Update Key (the only items that are updatable are the metadata items)
    public func update(key: EosioVault.VaultKey) -> Bool {
        return saveKeyMetadata(eosioPublicKey: key.eosioPublicKey, dictionary: key.metadata)
    }
    
    
    /// Get all Vault keys by combining all keychain keys (exculuding special vault identifier key) and all key metadata
    public func getAllVaultKeys() throws -> [EosioVault.VaultKey] {
        var vaultKeys = [String:VaultKey]()
        
        // add all ecKeys to the dict
        let ecKeys = try keychain.getAllEllipticCurveKeys()
        for ecKey in ecKeys {
            if ecKey.tag != vaultTag {
                if let vaultKey = VaultKey(ecKey: ecKey, metadata: nil) {
                    vaultKeys[vaultKey.eosioPublicKey] = vaultKey
                }
            }
        }
        
        // add metadata
        let allMetadata = getAllKeysMetadata() ?? [String:[String:Any]]()
        for (name,metadata) in allMetadata {
            if var vaultKey = vaultKeys[name] ?? VaultKey(eosioPublicKey: name, ecKey: nil, metadata: metadata) {
                vaultKey.metadata = metadata
                vaultKeys[name] = vaultKey
            }
        }
        return Array(vaultKeys.values)
    }
    
    
    /// Get the vault key for the eosioPublicKey
    public func getVaultKey(eosioPublicKey: String) throws -> EosioVault.VaultKey {
        let pubKeyData = try Data(eosioPublicKey: eosioPublicKey)
        let ecKey = keychain.getEllipticCurveKey(publicKey: pubKeyData)
        let metadata = getKeyMetadata(eosioPublicKey: eosioPublicKey)
        if let key = EosioVault.VaultKey(ecKey: ecKey, metadata: metadata) {
            return key
        } else {
            throw EosioError(EosioErrorCode.keyManagementError, reason: "\(eosioPublicKey) not found")
        }
    }
    
    
    /// Sign message with the private key corresponding to the public key if the private key is found in the keychain.
    /// Throws an error if the public key is not valid or the key is not found.
    public func sign(message: Data, eosioPublicKey: String, requireBio: Bool, completion: @escaping (String?, EosioError?)-> Void) {
        do {
            let vaultKey = try getVaultKey(eosioPublicKey: eosioPublicKey)
            sign(message: message, vaultKey: vaultKey, requireBio: requireBio, completion: completion)
        } catch {
            completion(nil, error.eosioError)
        }
    }
    
    
    private func sign(message: Data, vaultKey: VaultKey, requireBio: Bool, completion: @escaping (String?, EosioError?)-> Void) {
        // if require bio and the bio factor is none, then sign with software bio check
        if requireBio && vaultKey.bioFactor == .none {
            return signWithBioCheck(message: message, vaultKey: vaultKey, completion: completion)
        }
        // otherwise just sign
        DispatchQueue.main.async {
            do {
                let sig = try self.sign(message: message, vaultKey: vaultKey)
                completion(sig, nil)
            } catch {
                completion(nil, error.eosioError)
            }
        }
    }
    
    
    private func signWithBioCheck(message: Data, vaultKey: VaultKey, completion: @escaping (String?, EosioError?)-> Void) {
        context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return completion(nil, error?.eosioError)
        }
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Sign Transaction", reply: { (isValid, error) in
            if isValid {
                do {
                    let sig = try self.sign(message: message, vaultKey: vaultKey)
                    completion(sig, nil)
                } catch {
                    let eosioError = EosioError(.keySigningError, reason: error.localizedDescription, originalError: error as NSError?)
                    completion(nil, eosioError)
                }
            }
            
            if let error = error {
                switch error{
                case LAError.appCancel: //Request expiration has occurred and the app has canceled the biometrics authentication.
                    return
                default:
                    let eosioError = EosioError(.keySigningError, reason: error.localizedDescription, originalError: error as NSError?)
                    completion(nil, eosioError)
                }
            }
        })
    }
    
    
    /// Dismisses boimetrics dialogue and cancels the sign request.
    public func cancelPendingSigningRequest() {
        context?.invalidate()
    }
    
    
    /// Sign message with the private key corresponding to the public key if the private key is found in the keychain.
    /// Throws an error if the public key is not valid or the key is not found.
    private func sign(message: Data, vaultKey: VaultKey) throws -> String {
        guard let privateSecKey = vaultKey.privateSecKey else {
            throw EosioError(.keySigningError, reason: "Unable to get private key reference for \(vaultKey.eosioPublicKey)")
        }
        guard let uncompressedPublicKey = vaultKey.uncompressedPublicKey else {
            throw EosioError(.keySigningError, reason: "Unable to get uncompressed public key for \(vaultKey.eosioPublicKey)")
        }
        
        // If R1, sign using keychain
        if vaultKey.curve == .r1 {
            let der = try keychain.sign(privateKey: privateSecKey, data: message)
            guard let sig = EcdsaSignature(der: der as Data) else {
                throw EosioError(.keySigningError, reason: "Unable to create EcdsaSignature for \(der)")
            }
            let recid = try EccRecoverKey.recid(signatureDer: sig.der, message: message.sha256, targetPublicKey: uncompressedPublicKey)
            let headerByte: UInt8 = 27 + 4 + UInt8(recid)
            return Data([headerByte] + sig.r + sig.s).toEosioR1Signature
        }
        
        // If K1, sign using EosioSwiftEcc (uses openSSL)
        if vaultKey.curve == .k1 {
            guard let privateKey = privateSecKey.externalRepresentation?.suffix(32) else {
                throw EosioError(.keySigningError, reason: "Unable to get private key for \(vaultKey.eosioPublicKey)")
            }
            let sig = try EosioEccSign.signWithK1(publicKey: uncompressedPublicKey, privateKey: privateKey, data: message)
            return sig.toEosioK1Signature
        }

        throw EosioError(.keySigningError, reason: "Cannot sign with key \(vaultKey.eosioPublicKey)")
    }
    
    
    /// Save metadata for the eosioPublicKey
    public func saveKeyMetadata(eosioPublicKey: String, dictionary: [String:Any]) -> Bool {
        guard let json = dictionary.jsonString else { return false }
        return saveKeyMetadata(eosioPublicKey: eosioPublicKey, json: json)
    }
    
    
    /// Save metadata for the eosioPublicKey
    private func saveKeyMetadata(eosioPublicKey: String, json: String) -> Bool {
        let name = eosioPublicKey
        var result = false
        if let _ = getKeyMetadata(eosioPublicKey: eosioPublicKey) {
            result = keychain.updateValue(name: name, value: json, service: eosioKeyMetadataService)
        } else {
            result = keychain.saveValue(name: name, value: json, service: eosioKeyMetadataService)
        }
        if result == true {
            postUpdateNotification(eosioPublicKey: eosioPublicKey, action: "metadata update")
        }
        return result
    }
    
    
    /// Delete metadata for the eosioPublicKey
    public func deleteKeyMetadata(publicKey: String) {
        keychain.delete(name: publicKey, service: eosioKeyMetadataService)
    }
    
    
    /// Get metadata for the eosioPublicKey
    public func getKeyMetadata(eosioPublicKey: String) -> [String:Any]? {
        guard let json = keychain.getValue(name: eosioPublicKey, service: eosioKeyMetadataService) else { return nil }
        return json.toJsonDictionary
    }
    
    
    /// Get metadata for all Keys
    public func getAllKeysMetadata() -> [String:[String:Any]]? {
        guard let values = keychain.getValues(service: eosioKeyMetadataService) else { return nil }
        var keyMetadataArray = [String:[String:Any]]()
        for (name,value) in values {
            if let dictionary = value.toJsonDictionary {
                keyMetadataArray[name] = dictionary
            }
        }
        return keyMetadataArray
    }
    
    
}










