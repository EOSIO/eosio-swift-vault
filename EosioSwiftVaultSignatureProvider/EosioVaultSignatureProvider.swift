//
//  EosioVaultSignatureProvider.swift
//  EosioSwiftVaultSignatureProvider
//
//  Created by Todd Bowden on 4/9/19.
//  Copyright (c) 2018-2019 block.one
//

import Foundation
import EosioSwift
import EosioSwiftEcc
import EosioSwiftVault

public final class EosioVaultSignatureProvider: EosioSignatureProviderProtocol {

    private let vault: EosioVault
    public var requireBio = false
    
    /// Init an instance of EosioVaultSignatureProvider
    ///
    /// - Parameter accessGroup: The access group to create an instance of EosioVault
    /// - Parameter requireBio: Require bio identification for all signatures even if the key does not require it.
    public init(accessGroup: String, requireBio: Bool = false) {
        vault = EosioVault(accessGroup: accessGroup)
        self.requireBio = requireBio
    }
    
    
    /// Sign a transaction using an instance of EosioVault with the specified accessGroup
    ///
    /// - Parameters:
    ///   - request: The transaction signature request
    ///   - completion: The transaction signature response
    public func signTransaction(request: EosioTransactionSignatureRequest, completion: @escaping (EosioTransactionSignatureResponse) -> Void) {
        var response = EosioTransactionSignatureResponse()
      
        guard let chainIdData = try? Data(hex: request.chainId) else {
            response.error = EosioError(.signatureProviderError, reason: "\(request.chainId) is not a valid chain id")
            return completion(response)
        }
        let zeros = Data(repeating: 0, count: 32)
        let message = chainIdData + request.serializedTransaction + zeros
        sign(message: message, publicKeys: request.publicKeys) { (signatures, error) in
            guard let signatures = signatures else {
                response.error = error
                return completion(response)
            }
            var signedTransaction = EosioTransactionSignatureResponse.SignedTransaction()
            signedTransaction.signatures = signatures
            signedTransaction.serializedTransaction = request.serializedTransaction
            response.signedTransaction = signedTransaction
            completion(response)
        }
    
    }
    
    /// Recursive function to sign a message with public keys. If there are multiple keys, the func will sign with the first and call itself with the remaining keys.
    private func sign(message: Data, publicKeys: [String], completion: @escaping ([String]?, EosioError?) -> Void) {
        guard let firstPublicKey = publicKeys.first else {
            return completion([String](), nil)
        }
        vault.sign(message: message, eosioPublicKey: firstPublicKey, requireBio: requireBio) { [weak self] (signature, error) in
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
            strongSelf.sign(message: message, publicKeys: remainingPublicKeys, completion: { (signatures, error) in
                guard let signatures = signatures else {
                    return completion(nil, error)
                }
                completion([signature] + signatures, nil)
            })
        }
    }
    
    
    
    /// Get all available eosio keys for the instance of EosioVault with the specified accessGroup
    ///
    /// - Parameter completion: The available keys response
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
