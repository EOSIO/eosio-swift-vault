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
import BigInt
import CommonCrypto

/// General class for interacting with the Keychain and Secure Enclave.
public class Keychain {

    /// Accessibility of keychain item.
    public enum AccessibleProtection {
        case whenUnlocked
        case afterFirstUnlock
        case whenPasscodeSetThisDeviceOnly
        case whenUnlockedThisDeviceOnly
        case afterFirstUnlockThisDeviceOnly

        var cfstringValue: CFString {
            switch self {
            case .whenUnlocked:
                return kSecAttrAccessibleWhenUnlocked
            case .afterFirstUnlock:
                return kSecAttrAccessibleAfterFirstUnlock
            case .whenPasscodeSetThisDeviceOnly:
                return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
            case .whenUnlockedThisDeviceOnly:
                return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            case .afterFirstUnlockThisDeviceOnly:
                return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            }
        }
    }

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
    ///   - value: The value to save as String.
    ///   - service: The service associated with this item.
    ///   - protection: The device status protection level associated with this item.
    ///   - bioFactor: The biometric presence factor associated with this item.
    /// - Returns: True if saved, otherwise false.
    public func saveValue(name: String,
                          value: String,
                          service: String,
                          protection: AccessibleProtection = .afterFirstUnlockThisDeviceOnly,
                          bioFactor: BioFactor = .none) -> Bool {
        guard let data = value.data(using: String.Encoding.utf8) else { return false }
        return saveValue(name: name,
                         value: data,
                         service: service,
                         protection: protection,
                         bioFactor: bioFactor)
    }

    /// Save a value to the Keychain.
    ///
    /// - Parameters:
    ///   - name: The name associated with this item.
    ///   - value: The value to save as Data.
    ///   - service: The service associated with this item.
    ///   - protection: The device status protection level associated with this item.
    ///   - bioFactor: The biometric presence factor associated with this item.
    /// - Returns: True if saved, otherwise false.
    public func saveValue(name: String,
                          value: Data,
                          service: String,
                          protection: AccessibleProtection = .afterFirstUnlockThisDeviceOnly,
                          bioFactor: BioFactor = .none) -> Bool {

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: name,
            kSecAttrService as String: service,
            kSecValueData as String: value,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrSynchronizable as String: false,
            kSecAttrIsInvisible as String: true
        ]

        // Due to a bug in the iOS simulator when it is running iOS 13, adding values
        // to the keychain with kSecAttrAccessControl makes them unreadable in the
        // simulator only.  Works fine on real devices.  So if biometrics are not
        // desired, use kSecAttrAccessible instead to allow the simulator to be used
        // in these circumstances.  Filed as: http://openradar.appspot.com/7251207
        // Hopefully Apple will fix this at some point.
        switch bioFactor {
        case .fixed,
             .flex:
            guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
            protection.cfstringValue,
            bioFactor.accessFlag ?? [],
            nil) else { return false }
            query[kSecAttrAccessControl as String] = access
        case .none:
            query[kSecAttrAccessible as String] = protection.cfstringValue
        }

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
        return updateValue(name: name, value: data, service: service)
    }

    /// Update a value in the Keychain.
    ///
    /// - Parameters:
    ///   - name: The name associated with this item.
    ///   - value: The updated value.
    ///   - service: The service associated with this item.
    /// - Returns: True if updated, otherwise false.
    public func updateValue(name: String, value: Data, service: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: name,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: accessGroup
        ]
        let attributes: [String: Any] = [kSecValueData as String: value]
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
    /// - Returns: The value for the specified item as Data.
    public func getValueAsData(name: String, service: String) -> Data? {
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
        return data as Data
    }

    /// Get a value from the Keychain.
    ///
    /// - Parameters:
    ///   - name: The name of the item.
    ///   - service: The service associated with this item.
    /// - Returns: The value for the specified item as String.
    public func getValue(name: String, service: String) -> String? {
        guard let data = getValueAsData(name: name, service: service) else { return nil }
        guard let value = String(data: data, encoding: .utf8) else { return nil }
        return value
    }

    /// Get a dictionary of values from the Keychain for the specified service.
    ///
    /// - Parameter service: A service name.
    /// - Returns: A dictionary of names and Data values for the specified service.
    public func getValuesAsData(service: String) -> [String: Data]? {
        var values = [String: Data]()

        guard let array = getValuesAsAny(service: service) else { return nil }

        for item in array {
            if let name = item[kSecAttrAccount as String] as? String, let data = item["v_Data"] as? Data {
                values[name] = data
            }
        }
        return values
    }

    /// Get a dictionary of values from the Keychain for the specified service.
    ///
    /// - Parameter service: A service name.
    /// - Returns: A dictionary of names and String values for the specified service.
    public func getValues(service: String) -> [String: String]? {
        var values = [String: String]()

        guard let array = getValuesAsAny(service: service) else { return nil }
        for item in array {
            if let name = item[kSecAttrAccount as String] as? String, let data = item["v_Data"] as? Data, let value = String(data: data as Data, encoding: .utf8) {
                values[name] = value
            }
        }
        return values
    }

    /// Retrieve all values for service
    private func getValuesAsAny(service: String) -> [[String: Any]]? {
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

        guard let array = items as? [[String: Any]] else { return nil }
        return array
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
    private func makeQueryForAllEllipticCurveKeys(tag: String? = nil, label: String? = nil, secureEnclave: Bool = false ) -> [String: Any] {
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
        if let label = label {
            query[kSecAttrLabel as String] = label
        }
        if secureEnclave {
            query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
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
    /// IMPORTANT: If the key  requires a biometric check for access, the system will prompt the user for FaceID/TouchID
    ///
    /// - Parameter publicKey: The public key.
    /// - Returns: An ECKey corresponding to the public key.
    public func getEllipticCurveKey(publicKey: Data) -> ECKey? {
        do {
            let eckey: ECKey = try getEllipticCurveKey(publicKey: publicKey)
            return eckey
        } catch {
            return nil
        }
    }

    /// Get all elliptic curve keys with option to filter by tag.
    /// IMPORTANT: If any of the keys returned by the  search query require a biometric check for access, the system will prompt the user for FaceID/TouchID
    ///
    /// - Parameter tag: The tag to filter by (defaults to `nil`).
    /// - Returns: An array of ECKeys.
    /// - Throws: If there is an error in the key query.
    public func getAllEllipticCurveKeys(tag: String? = nil, label: String? = nil) throws -> [ECKey] {
        var keys = [ECKey]()
        let array = try getAttributesForAllEllipticCurveKeys(tag: tag, label: label)
        for attributes in array {
            if let key = ECKey(attributes: attributes) {
                keys.append(key)
            } else {
                // if error try to lookup this key again using the applicationLabel (sha1 of the public key)
                // sometimes if there are a large number of keys returned, the key ref seems to be missing, but getting the key again with the application label works
                if let applicationLabel = attributes[kSecAttrApplicationLabel as String] as? Data, let key = try? getEllipticCurveKey(applicationLabel: applicationLabel) {
                    keys.append(key)
                }
            }
        }
        if keys.count == 0 && array.count > 0 {
            throw EosioError(.keyManagementError, reason: "Unable to create any ECKeys from \(array.count) items.")
        }
        return keys
    }

    /// Get all attributes for elliptic curve keys with option to filter by tag.
    /// IMPORTANT: If any of the keys returned by the  search query require a biometric check for access, the system will prompt the user for FaceID/TouchID
    ///
    /// - Parameter tag: The tag to filter by (defaults to `nil`).
    /// - Returns: An array of ECKeys.
    /// - Throws: If there is an error in the key query.
    public func getAttributesForAllEllipticCurveKeys(tag: String? = nil, label: String? = nil, matchLimitAll: Bool = true) throws -> [[String: Any]] {
        var query: [String: Any] =  [
            kSecClass as String: kSecClassKey,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true
        ]
        if matchLimitAll {
            query[kSecMatchLimit as String] = kSecMatchLimitAll
        } else {
            query[kSecMatchLimit as String] = kSecMatchLimitOne
        }
        if let tag = tag {
            query[kSecAttrApplicationTag as String] = tag
        }
        if let label = label {
            query[kSecAttrLabel as String] = label
        }
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        if status == errSecItemNotFound {
            return [[String: Any]]()
        }
        guard status == errSecSuccess else {
            throw EosioError(.keyManagementError, reason: "Get Attributes query error \(status).")
        }
        guard let array = items as? [[String: Any]] else {
            throw EosioError(.keyManagementError, reason: "Get Attributes items not an array of dictionaries.")
        }
        return array
    }

    /// Get an elliptic curve keys for the provided application label (for ec keys this is the sha1 hash of the public key)
    /// IMPORTANT: If the key  requires a biometric check for access, the system will prompt the user for FaceID/TouchID
    ///
    /// - Parameter applicationLabel: The application label to search for
    /// - Throws: If there is a error getting the key
    /// - Returns: An ECKey
    public func getEllipticCurveKey(applicationLabel: Data) throws -> ECKey {
        //print(applicationLabel.hex)
        let query: [String: Any] =  [
            kSecClass as String: kSecClassKey,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrApplicationLabel as String: applicationLabel
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            throw EosioError(.keyManagementError, reason: "\(applicationLabel) not found.")
        }
        guard status == errSecSuccess else {
            throw EosioError(.keyManagementError, reason: "Get key query error \(status)")
        }
        guard let attributes = item as? [String: Any] else {
            throw EosioError(.keyManagementError, reason: "Cannot get attributes for \(applicationLabel)")
        }
        return try ECKey.new(attributes: attributes)
    }

    /// Get an elliptic curve keys for the provided public key
    /// IMPORTANT: If the key  requires a biometric check for access, the system will prompt the user for FaceID/TouchID
    ///
    /// - Parameter publicKey: The publickey
    /// - Throws: If there is a error getting the key
    /// - Returns: An ECKey
    public func getEllipticCurveKey(publicKey: Data) throws -> ECKey {
        let uncPublicKey = try uncompressedPublicKey(data: publicKey)
        return try getEllipticCurveKey(applicationLabel: uncPublicKey.sha1)
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
    /// IMPORTANT: If any of the keys returned by the  search query require a biometric check for access, the system will prompt the user for FaceID/TouchID
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
    /// IMPORTANT: If the key  requires a biometric check for access, the system will prompt the user for FaceID/TouchID
    ///
    /// - Parameter publicKey: A public key in either compressed or uncompressed format.
    /// - Returns: A SecKey.
    public func getPrivateSecKey(publicKey: Data) -> SecKey? {
        return getEllipticCurveKey(publicKey: publicKey)?.privateSecKey
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

    /// Calculate the Y component of an elliptic curve from the X and the curve params
    /// - Parameters:
    ///   - x: x
    ///   - a: curve param a
    ///   - b: curve param b
    ///   - p: curve param p
    ///   - isOdd: isOdd
    /// - Returns: The Y component as a bigUInt
    func ellipticCurveY(x: BigInt, a: BigInt, b: BigInt, p: BigInt, isOdd: Bool) -> BigUInt { // swiftlint:disable:this identifier_name
        let y2 = (x.power(3, modulus: p) + (a * x) + b).modulus(p) // swiftlint:disable:this identifier_name
        var y = y2.power((p+1)/4, modulus: p) // swiftlint:disable:this identifier_name
        let yMod2 = y.modulus(2)
        if isOdd && yMod2 != 1 || !isOdd && yMod2 != 0 {
            y = p - y
        }
        return BigUInt(y)
    }

    /// Compute the uncompressed public key from the compressed key
    /// - Parameter data: A public key
    /// - Parameter curve: The curve (R1 and K1 are supported)
    /// - Throws: If the data is not a valid public key
    /// - Returns: The uncompressed public key
    func uncompressedPublicKey(data: Data, curve: String = "R1") throws -> Data {
        guard let firstByte = data.first else {
            throw EosioError(.keyManagementError, reason: "No key data provided.")
        }
        guard firstByte == 2 || firstByte == 3 || firstByte == 4 else {
            throw EosioError(.keyManagementError, reason: "\(data.hex) is not a valid public key.")
        }
        if firstByte == 4 {
            guard data.count == 65 else {
                throw EosioError(.keyManagementError, reason: "\(data.hex) is not a valid public key. Expecting 65 bytes.")
            }
            return data
        }
        guard data.count == 33 else {
            throw EosioError(.keyManagementError, reason: "\(data.hex) is not a valid public key. Expecting 33 bytes.")
        }

        let xData = data[1..<data.count]
        let x = BigInt(BigUInt(xData))
        var p: BigInt // swiftlint:disable:this identifier_name
        var a: BigInt // swiftlint:disable:this identifier_name
        var b: BigInt // swiftlint:disable:this identifier_name

        switch curve.uppercased() {
        case "R1" :
            p = BigInt(BigUInt(Data(hexString: "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")!))
            a = BigInt(-3)
            b = BigInt(BigUInt(Data(hexString: "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")!))
        case "K1" :
            p = BigInt(BigUInt(Data(hexString: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")!))
            a = BigInt(0)
            b = BigInt(7)
        default:
            throw EosioError(.keyManagementError, reason: "\(curve) is not a valid curve.")
        }

        let y = ellipticCurveY(x: x, a: a, b: b, p: p, isOdd: firstByte == 3) // swiftlint:disable:this identifier_name
        let four: UInt8 = 4
        var yData = y.serialize()
        while yData.count < 32 {
            yData = [0x00] + yData
        }
        return [four] + xData + yData
    }

    /// Import an external elliptic curve private key into the Keychain.
    ///
    /// - Parameters:
    ///   - privateKey: The private key as data (97 bytes).
    ///   - tag: A tag to associate with this key.
    ///   - label: A label to associate with this key.
    ///   - protection: Accessibility defaults to .whenUnlockedThisDeviceOnly.
    ///   - accessFlag: The accessFlag for this key.
    /// - Returns: The imported key as an ECKey.
    /// - Throws: If the key is not valid or cannot be imported.
    // swiftlint:disable:next cyclomatic_complexity
    public func importExternal(privateKey: Data, tag: String? = nil, label: String?  = nil, // swiftlint:disable:this function_body_length
                               protection: AccessibleProtection = .whenUnlockedThisDeviceOnly,
                               accessFlag: SecAccessControlCreateFlags? = nil) throws -> ECKey {

        //check data length
        guard privateKey.count == 97 else {
            throw EosioError(.keyManagementError, reason: "Private Key data should be 97 bytes, found \(privateKey.count) bytes")
        }

        let publicKey = privateKey.prefix(65)
        if getEllipticCurveKey(publicKey: publicKey) != nil {
            throw EosioError(.keyManagementError, reason: "Key already exists")
        }

        guard let access = makeSecSecAccessControl(secureEnclave: false, protection: protection, accessFlag: accessFlag) else {
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

        // We need to add:
        //
        // kSecAttrAccessControl as String: access
        //
        // to this to make the system respect the biometric requirements for access.
        // However if we do that right now the import process does several readbacks
        // and this triggers the biometric challenges, which is not what we want to
        // do.  We'll need to rework the import flow to not require those readbacks
        // before we can add that here and fix the issue.  SMM 2020/04/07
        //
        // Added. See comment below. THB 2020/05/13
        attributes = [
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: secKey,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrAccessControl as String: access
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

        // Previously at this point the key was read back from the keychain and returned. (See comment above)
        // However, if the key had a biometric restriction, the system would prompt with a biometric challenge.
        // So, instead construct the key attributes dictionary from in scope data to create the ECKey to return
        var keyatt: [String: Any] = [
            kSecAttrAccessGroup as String: accessGroup,
            kSecValueRef as String: secKey
        ]
        if let tag = tag {
            keyatt[kSecAttrApplicationTag as String] = tag
        }
        if let label = label {
            keyatt[kSecAttrLabel as String] = label
        }
        let key = try ECKey.new(attributes: keyatt)
        return key
    }

    /// Make SecAccessControl
    private func makeSecSecAccessControl(secureEnclave: Bool,
                                         protection: AccessibleProtection = .whenUnlockedThisDeviceOnly,
                                         accessFlag: SecAccessControlCreateFlags? = nil) -> SecAccessControl? {
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
            protection.cfstringValue,
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
    ///   - protection: Accessibility defaults to whenUnlockedThisDeviceOnly.
    ///   - accessFlag: The accessFlag for this key.
    /// - Returns: A SecKey.
    /// - Throws: If a key cannot be created.
    public func createEllipticCurveSecKey(secureEnclave: Bool, tag: String? = nil, label: String? = nil,
                                          protection: AccessibleProtection = .whenUnlockedThisDeviceOnly,
                                          accessFlag: SecAccessControlCreateFlags? = nil) throws -> SecKey {
        guard let access = makeSecSecAccessControl(secureEnclave: secureEnclave, protection: protection, accessFlag: accessFlag) else {
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

    /// Create a new elliptic curve key.
    ///
    /// - Parameters:
    ///   - secureEnclave: Generate this key in Secure Enclave?
    ///   - tag: A tag to associate with this key.
    ///   - label: A label to associate with this key.
    ///   - protection: Accessibility defaults to whenUnlockedThisDeviceOnly.
    ///   - accessFlag: The accessFlag for this key.
    /// - Returns: An ECKey.
    /// - Throws: If a key cannot be created.
    public func createEllipticCurveKey(secureEnclave: Bool, tag: String? = nil, label: String? = nil,
                                       protection: AccessibleProtection = .whenUnlockedThisDeviceOnly,
                                       accessFlag: SecAccessControlCreateFlags? = nil) throws -> ECKey {

        let secKey = try createEllipticCurveSecKey(secureEnclave: secureEnclave, tag: tag, label: label, protection: protection, accessFlag: accessFlag)

        var keyatt: [String: Any] = [
            kSecAttrAccessGroup as String: accessGroup,
            kSecValueRef as String: secKey
        ]
        if let tag = tag {
            keyatt[kSecAttrApplicationTag as String] = tag
        }
        if let label = label {
            keyatt[kSecAttrLabel as String] = label
        }
        let key = try ECKey.new(attributes: keyatt)
        return key
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

private extension Data {

    var toUnsafeMutablePointerBytes: UnsafeMutablePointer<UInt8> {
        let pointerBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: self.count)
        self.copyBytes(to: pointerBytes, count: self.count)
        return pointerBytes
    }

    var toUnsafePointerBytes: UnsafePointer<UInt8> {
        return UnsafePointer(self.toUnsafeMutablePointerBytes)
    }

    /// Returns the SHA1hash of the data.
    var sha1: Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        let p = self.toUnsafePointerBytes // swiftlint:disable:this identifier_name
        _ = CC_SHA1(p, CC_LONG(self.count), &hash)
        p.deallocate()
        return Data(hash)
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
        let compressedKey = Data([flag]) + x
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
