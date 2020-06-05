//
//  EosioVaultSignatureProvider.swift
//  EosioSwiftVaultSignatureProvider
//
//  Created by Todd Bowden on 4/9/19.
//  Copyright (c) 2017-2019 block.one and its contributors. All rights reserved.
//

import Foundation
import EosioSwift
import EosioSwiftVault

/// Signature provider implementation for EOSIO SDK for Swift using Keychain and/or Secure Enclave.
public final class EosioVaultSignatureProvider: EosioSignatureProviderProtocol {

    private let vault: EosioVault

    /// Require biometric identification for all signatures even if the key does not require it. Defaults to `false`.
    public var requireBio = false

    /// Init an instance of EosioVaultSignatureProvider.
    ///
    /// - Parameters:
    ///     - accessGroup: The access group to create an instance of EosioVault.
    ///     - requireBio: Require biometric identification for all signatures even if the key does not require it. Defaults to `false`.
    public init(accessGroup: String, requireBio: Bool = false) {
        vault = EosioVault(accessGroup: accessGroup)
        self.requireBio = requireBio
    }

    /// Sign a transaction using an instance of EosioVault with the specified accessGroup.
    ///
    /// - Parameters:
    ///   - request: The transaction signature request.
    ///   - completion: The transaction signature response.
    public func signTransaction(request: EosioTransactionSignatureRequest,
                                completion: @escaping (EosioTransactionSignatureResponse) -> Void) {
        self.signTransaction(request: request, prompt: "Sign Transaction", completion: completion)
    }

    /// Sign a transaction using an instance of EosioVault with the specified accessGroup.
    ///
    /// - Parameters:
    ///   - request: The transaction signature request.
    ///   - prompt: Prompt for biometric authentication if required.
    ///   - completion: The transaction signature response.
    public func signTransaction(request: EosioTransactionSignatureRequest,
                                prompt: String,
                                completion: @escaping (EosioTransactionSignatureResponse) -> Void) {
        var response = EosioTransactionSignatureResponse()

        guard let chainIdData = try? Data(hex: request.chainId) else {
            response.error = EosioError(.signatureProviderError, reason: "\(request.chainId) is not a valid chain id")
            return completion(response)
        }
        var contextFreeDataHash = Data(repeating: 0, count: 32)
        if request.serializedContextFreeData.count > 0 {
            contextFreeDataHash = request.serializedContextFreeData.sha256
        }
        let message = chainIdData + request.serializedTransaction + contextFreeDataHash
        sign(message: message, publicKeys: request.publicKeys, prompt: prompt) { (signatures, error) in
            guard let signatures = signatures else {
                response.error = error
                return completion(response)
            }
            guard signatures.count > 0 else {
                response.error = EosioError(.signatureProviderError, reason: "No signatures")
                return completion(response)
            }
            var signedTransaction = EosioTransactionSignatureResponse.SignedTransaction()
            signedTransaction.signatures = signatures
            signedTransaction.serializedTransaction = request.serializedTransaction
            signedTransaction.serializedContextFreeData = request.serializedContextFreeData
            response.signedTransaction = signedTransaction
            completion(response)
        }

    }

    /// Recursive function to sign a message with public keys. If there are multiple keys, the function will sign with the first and call itself with the remaining keys.
    private func sign(message: Data, publicKeys: [String], prompt: String, completion: @escaping ([String]?, EosioError?) -> Void) {
        guard let firstPublicKey = publicKeys.first else {
            return completion([String](), nil)
        }
        vault.sign(message: message, eosioPublicKey: firstPublicKey, requireBio: requireBio, prompt: prompt) { [weak self] (signature, error) in
            guard let signature = signature else {
                return completion(nil, error)
            }
            var remainingPublicKeys = publicKeys
            remainingPublicKeys.removeFirst()

            if remainingPublicKeys.count == 0 {
                return completion([signature], nil)
            }
            guard let strongSelf = self else {
                return completion(nil, EosioError(.unexpectedError, reason: "self does not exist"))
            }
            strongSelf.sign(message: message, publicKeys: remainingPublicKeys, prompt: prompt, completion: { (signatures, error) in
                guard let signatures = signatures else {
                    return completion(nil, error)
                }
                completion([signature] + signatures, nil)
            })
        }
    }

    /// Get all available EOSIO keys for the instance of EosioVault with the specified accessGroup.
    ///
    /// - Parameters:
    ///     - completion: The available keys response.
    public func getAvailableKeys(completion: @escaping (EosioAvailableKeysResponse) -> Void) {
        var response = EosioAvailableKeysResponse()
        do {
            let vaultKeys = try vault.getAllVaultKeys()
            response.keys = vaultKeys.compactMap({ (vaultKey) -> String? in
                return vaultKey.eosioPublicKey
            })
            completion(response)
        } catch {
            response.error = error.eosioError
            completion(response)
        }
    }
}
