//
//  Keychain.swift
//  EosioSwiftVault
//
//  Created by Todd Bowden on 7/11/18.
//  Copyright (c) 2017-2019 block.one and its contributors. All rights reserved.
//

import Foundation
import Security
import EosioSwift

/// General class for interacting with the Keychain and Secure Enclave.
public class Keychain {

    /// The accessGroup allows multiple apps (including extensions) in the same team to share the same Keychain.
    public let accessGroup: String

    /// Init with accessGroup. The accessGroup allows multiple apps (including extensions) in the same team to share the same Keychain.
    ///
    /// - Parameter accessGroup: The access group should be an `App Group` on the developer account.
    public init(accessGroup: String) {
        self.accessGroup = accessGroup
    }

    /// Save a value to the Keychain.
    ///
    /// - Parameters:
    ///   - name: The name associated with this item.
    ///   - value: The value to save.
    ///   - service: The service associated with this item.
    /// - Returns: True if saved, otherwise false.
    public func saveValue(name: String, value: String, service: String) -> Bool {
        guard let data = value.data(using: String.Encoding.utf8) else { return false }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: name,
            kSecAttrService as String: service,
            kSecValueData as String: data,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrSynchronizable as String: false,
            kSecAttrIsInvisible as String: true
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Update a value in the Keychain.
    ///
    /// - Parameters:
    ///   - name: The name associated with this item.
    ///   - value: The updated value.
    ///   - service: The service associated with this item.
    /// - Returns: True if updated, otherwise false.
    public func updateValue(name: String, value: String, service: String) -> Bool {
        guard let data = value.data(using: String.Encoding.utf8) else { return false }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: name,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: accessGroup
        ]
        let attributes: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        return status == errSecSuccess
    }

    /// Delete an item from the Keychain.
    ///
    /// - Parameters:
    ///   - name: The name of the item to delete.
    ///   - service: The service associated with this item.
    public func delete(name: String, service: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: name,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: accessGroup
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Get a value from the Keychain.
    ///
    /// - Parameters:
    ///   - name: The name of the item.
    ///   - service: The service associated with this item.
    /// - Returns: The value for the specified item.
    public func getValue(name: String, service: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: name,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnData as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { return nil }
        let data = item as! CFData // swiftlint:disable:this force_cast
        guard let value = String(data: data as Data, encoding: .utf8) else { return nil }
        return value
    }

    /// Get a dictionary of values from the Keychain for the specified service.
    ///
    /// - Parameter service: A service name.
    /// - Returns: A dictionary of names and values for the specified service.
    public func getValues(service: String) -> [String: String]? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: accessGroup,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true
        ]
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        guard status == errSecSuccess else { return nil }
        var values = [String: String]()

        guard let array = items as? [[String: Any]] else { return nil }
        for item in array {
            if let name = item[kSecAttrAccount as String] as? String, let data = item["v_Data"] as? Data, let value = String(data: data as Data, encoding: .utf8) {
                values[name] = value
            }
        }
        return values
    }

    /// Make query for Key.
    private func makeQueryForKey(key: SecKey) -> [String: Any] {
        return [
            kSecValueRef as String: key,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnRef as String: true
        ]
    }

    /// Make query for ecKey.
    private func makeQueryForKey(ecKey: ECKey) -> [String: Any] {
        let query: [String: Any] = [
            kSecValueRef as String: ecKey.privateSecKey,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnRef as String: true
        ]
        return query
    }

    /// Make query to retrieve all elliptic curve keys in the Keychain.
    private func makeQueryForAllEllipticCurveKeys(tag: String? = nil) -> [String: Any] {
        var query: [String: Any] =  [
            kSecClass as String: kSecClassKey,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnRef as String: true
        ]
        if let tag = tag {
            query[kSecAttrApplicationTag as String] = tag
        }
        return query
    }

    /// Delete key given the SecKey.
    ///
    /// - Parameter secKey: The SecKey to delete.
    public func deleteKey(secKey: SecKey) {
        let query = makeQueryForKey(key: secKey)
        SecItemDelete(query as CFDictionary)
    }

    /// Delete key if public key exists.
    ///
    /// - Parameter publicKey: The public key of the key to delete.
    public func deleteKey(publicKey: Data) {
        guard let privateSecKey = getPrivateSecKey(publicKey: publicKey) else { return }
        deleteKey(secKey: privateSecKey)
    }

    /// Update label.
    ///
    /// - Parameters:
    ///   - label: The new label value.
    ///   - publicKey: The public key of the key to update.
    public func update(label: String, publicKey: Data) {
        guard let ecKey = getEllipticCurveKey(publicKey: publicKey) else { return }
        let query = makeQueryForKey(ecKey: ecKey)
        let attributes: [String: Any] = [
            kSecAttrLabel as String: label
        ]
        _ = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }

    /// Get elliptic curve key -- getting the key from the Keychain given the key is used for testing.
    public func getSecKey(key: SecKey) -> SecKey? {
        let query = makeQueryForKey(key: key)
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { return nil }
        let key = item as! SecKey // swiftlint:disable:this force_cast
        return key
    }

    /// Get an elliptic curve key given the public key.
    ///
    /// - Parameter publicKey: The public key.
    /// - Returns: An ECKey corresponding to the public key.
    public func getEllipticCurveKey(publicKey: Data) -> ECKey? {
        guard let allKeys = try? getAllEllipticCurveKeys() else {
            return nil
        }
        for key in allKeys {
            if key.compressedPublicKey == publicKey || key.uncompressedPublicKey == publicKey {
                return key
            }
        }
        return nil
    }

    /// Get all elliptic curve keys with option to filter by tag.
    ///
    /// - Parameter tag: The tag to filter by (defaults to `nil`).
    /// - Returns: An array of ECKeys.
    /// - Throws: If there is an error in the key query.
    public func getAllEllipticCurveKeys(tag: String? = nil) throws -> [ECKey] {
        var query: [String: Any] =  [
            kSecClass as String: kSecClassKey,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true
        ]
        if let tag = tag {
            query[kSecAttrApplicationTag as String] = tag
        }
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        if status == errSecItemNotFound {
            return [ECKey]()
        }
        guard status == errSecSuccess else {
            throw EosioError(.keyManagementError, reason: "Get keys query error \(status)")
        }
        guard let array = items as? [[String: Any]] else {
            throw EosioError(.keyManagementError, reason: "Get keys items not an array of dictionaries")
        }
        var keys = [ECKey]()
        for item in array {
            if let key = ECKey(attributes: item) {
                keys.append(key)
            }
        }
        return keys
    }

    /// Get all elliptic curve private Sec Keys.
    /// For Secure Enclave private keys, the SecKey is a reference. It's not posible to export the actual private key data.
    ///
    /// - Parameter tag: The tag to filter by (defaults to `nil`).
    /// - Returns: An array of SecKeys.
    public func getAllEllipticCurvePrivateSecKeys(tag: String? = nil) -> [SecKey]? {
        let query = makeQueryForAllEllipticCurveKeys(tag: tag)
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        guard status == errSecSuccess else { return nil }
        guard let keys = items as? [SecKey] else { return nil }
        return keys
    }

    /// Get all elliptic curve keys and return the public keys.
    ///
    /// - Returns: An array of public SecKeys.
    public func getAllEllipticCurvePublicSecKeys() -> [SecKey]? {
        guard let privateKeys = getAllEllipticCurvePrivateSecKeys() else { return nil }
        var publicKeys = [SecKey]()
        for privateKey in privateKeys {
            if let publicKey = SecKeyCopyPublicKey(privateKey) {
                publicKeys.append(publicKey)
            }
        }
        return publicKeys
    }

    /// Get the private SecKey for the public key if the key exists in the Keychain.
    /// Public key data can be in either compressed or uncompressed format.
    ///
    /// - Parameter publicKey: A public key in either compressed or uncompressed format.
    /// - Returns: A SecKey.
    public func getPrivateSecKey(publicKey: Data) -> SecKey? {
        guard let allPrivateKeys = getAllEllipticCurvePrivateSecKeys() else { return nil }
        for privateKey in allPrivateKeys {
            if let uncompressedPubKey = privateKey.publicKey?.externalRepresentation {
                if uncompressedPubKey == publicKey || uncompressedPubKey.compressedPublicKey == publicKey {
                    return privateKey
                }
            }
        }
        return nil
    }

    /// Create a **NON**-Secure-Enclave elliptic curve private key.
    ///
    /// - Parameter isPermanent: Is the key stored permanently in the Keychain?
    /// - Returns: A SecKey.
    public func createEllipticCurvePrivateKey(isPermanent: Bool = false) -> SecKey? {

        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [], nil) else { return nil }

        let attributes: [String: Any] = [
            kSecUseAuthenticationUI as String: kSecUseAuthenticationContext,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: isPermanent,
                kSecAttrAccessControl as String: access
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            return nil
        }
        return privateKey
    }

    /// Import an external elliptic curve private key into the Keychain.
    ///
    /// - Parameters:
    ///   - privateKey: The private key as data (97 bytes).
    ///   - tag: A tag to associate with this key.
    ///   - label: A label to associate with this key.
    /// - Returns: The imported key as an ECKey.
    /// - Throws: If the key is not valid or cannot be imported.
    public func importExternal(privateKey: Data, tag: String? = nil, label: String?  = nil) throws -> ECKey {

        //check data length
        guard privateKey.count == 97 else {
            throw EosioError(.keyManagementError, reason: "Private Key data should be 97 bytes, found \(privateKey.count) bytes")
        }

        let publicKey = privateKey.prefix(65)
        if getEllipticCurveKey(publicKey: publicKey) != nil {
            throw EosioError(.keyManagementError, reason: "Key already exists")
        }

        guard let access = makeSecSecAccessControl(secureEnclave: false) else {
            throw EosioError(.keyManagementError, reason: "Error creating Access Control")
        }

        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrIsPermanent as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: access
            ]
        ]
        if let tag = tag {
            attributes[kSecAttrApplicationTag as String] = tag
        }
        if let label = label {
            attributes[kSecAttrLabel as String] = label
        }

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(privateKey as CFData, attributes as CFDictionary, &error) else {
            print(error.debugDescription)
            throw EosioError(.keyManagementError, reason: error.debugDescription)
        }

        attributes = [
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: secKey,
            kSecAttrAccessGroup as String: accessGroup
        ]
        if let tag = tag {
            attributes[kSecAttrApplicationTag as String] = tag
        }
        if let label = label {
            attributes[kSecAttrLabel as String] = label
        }

        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw EosioError(.keyManagementError, reason: "Unable to add key \(publicKey) to Keychain")
        }

        guard let key = getEllipticCurveKey(publicKey: publicKey) else {
            throw EosioError(.keyManagementError, reason: "Unable to find key \(publicKey) in Keychain")
        }
        return key
    }

    /// Make SecAccessControl
    private func makeSecSecAccessControl(secureEnclave: Bool, accessFlag: SecAccessControlCreateFlags? = nil) -> SecAccessControl? {
        var flags: SecAccessControlCreateFlags
        if let accessFlag = accessFlag {
            if secureEnclave {
                flags = [.privateKeyUsage, accessFlag]
            } else {
                flags = [accessFlag]
            }
        } else {
            if secureEnclave {
                flags = [.privateKeyUsage]
            } else {
                flags = []
            }
        }

        return SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            nil
        )
    }

    /// Create a new Secure Enclave key.
    ///
    /// - Parameters:
    ///   - tag: A tag to associate with this key.
    ///   - label: A label to associate with this key.
    ///   - accessFlag: accessFlag for this key.
    /// - Returns: A Secure Enclave SecKey.
    /// - Throws: If a key cannot be created.
    public func createSecureEnclaveSecKey(tag: String? = nil, label: String? = nil, accessFlag: SecAccessControlCreateFlags? = nil) throws -> SecKey {
        return try createEllipticCurveSecKey(secureEnclave: true, tag: tag, label: label, accessFlag: accessFlag)
    }

    /// Create a new elliptic curve key.
    ///
    /// - Parameters:
    ///   - secureEnclave: Generate this key in Secure Enclave?
    ///   - tag: A tag to associate with this key.
    ///   - label: A label to associate with this key.
    ///   - accessFlag: The accessFlag for this key.
    /// - Returns: A SecKey.
    /// - Throws: If a key cannot be created.
    public func createEllipticCurveSecKey(secureEnclave: Bool, tag: String? = nil, label: String? = nil, accessFlag: SecAccessControlCreateFlags? = nil) throws -> SecKey {
        guard let access = makeSecSecAccessControl(secureEnclave: secureEnclave, accessFlag: accessFlag) else {
            throw EosioError(.keyManagementError, reason: "Error creating Access Control")
        }

        var attributes: [String: Any] = [
            kSecUseAuthenticationUI as String: kSecUseAuthenticationContext,
            kSecUseOperationPrompt as String: "",
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrAccessGroup as String: accessGroup,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: access
            ]
        ]

        if secureEnclave {
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }

        if let tag = tag {
            attributes[kSecAttrApplicationTag as String] = tag
        }
        if let label = label {
            attributes[kSecAttrLabel as String] = label
        }

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw EosioError(.keyManagementError, reason: error.debugDescription)
        }
        return privateKey
    }

    /// Sign if the key is in the Keychain.
    ///
    /// - Parameters:
    ///   - publicKey: The public key corresponding to a private key to use for signing.
    ///   - data: The data to sign.
    /// - Returns: A signature.
    /// - Throws: If private key is not available.
    public func sign(publicKey: Data, data: Data) throws -> Data {
        guard let privateKey = getPrivateSecKey(publicKey: publicKey) else {
            throw EosioError(.keyManagementError, reason: "Private key is not available for public key \(publicKey.hex)")
        }
        return try sign(privateKey: privateKey, data: data)
    }

    /// Sign with Secure Enclave or Keychain.
    ///
    /// - Parameters:
    ///   - privateKey: The private key to use for signing.
    ///   - data: The data to sign.
    /// - Returns: A signature.
    /// - Throws: If an error is encountered attempting to sign.
    public func sign(privateKey: SecKey, data: Data) throws -> Data {
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw EosioError(.keySigningError, reason: "Algorithm \(algorithm) is not supported")
        }
        var error: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) else {
            throw EosioError(.keyManagementError, reason: error.debugDescription)
        }
        return der as Data
    }

    /// Decrypt data using `SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM`.
    ///
    /// - Parameters:
    ///   - publicKey: The public key corresponding to a private key to use for decrypting.
    ///   - message: The encrypted message.
    /// - Returns: The decrypted message.
    /// - Throws: If the private key is not found or the message cannot be decrypted.
    public func decrypt(publicKey: Data, message: Data) throws -> Data {
        // lookup ecKey in the Keychain
        guard let ecKey = getEllipticCurveKey(publicKey: publicKey) else {
            throw EosioError(.keyManagementError, reason: "key not found")
        }
        // decrypt
        var error: Unmanaged<CFError>?
        let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        guard let decryptedData = SecKeyCreateDecryptedData(ecKey.privateSecKey, algorithm, message as CFData, &error) else {
            throw EosioError(.keyManagementError, reason: error.debugDescription)
        }
        return decryptedData as Data
    }
}

public extension Data {

    /// Compress an uncompressed 65 byte public key to a 33 byte compressed public key.
    var compressedPublicKey: Data? {
        guard self.count == 65 else { return nil }
        let uncompressedKey = self
        guard uncompressedKey[0] == 4 else { return nil }
        let x = uncompressedKey[1...32]
        let yLastByte = uncompressedKey[64]
        let flag: UInt8 = 2 + (yLastByte % 2)
        let compressedKey = Data(bytes: [flag]) + x
        return compressedKey
    }

}

public extension SecKey {

    /// The externalRepresentation of a SecKey in ANSI X9.63 format.
    var externalRepresentation: Data? {
        var error: Unmanaged<CFError>?
        if let cfdata = SecKeyCopyExternalRepresentation(self, &error) {
            return cfdata as Data
        }
        return nil
    }

    /// The public key for a private SecKey.
    var publicKey: SecKey? {
        return SecKeyCopyPublicKey(self)
    }

}
