//
//  BioFactor.swift
//  EosioSwiftVault

//  Created by Steve McCoole on 4/7/20
//  Copyright (c) 2017-2020 block.one and its contributors. All rights reserved.
//

import Foundation

/// Setting on the key dictating biometric authentication requirements and whether the key persists after device's biometric settings are modified.
public enum BioFactor: String {
    /// Biometric authentication is not required for the key.
    case none = ""
    /// Keys persist even after the device's biometric settings are modified.
    case flex = "bio flex"
    /// Keys are bricked in the event the device's biometric settings are modified.
    case fixed = "bio fixed"

    var accessFlag: SecAccessControlCreateFlags? {
        switch self {
        case .flex:
            return .biometryAny
        case .fixed:
            return .biometryCurrentSet
        case .none:
            return nil
        }
    }

    var tag: String? {
        switch self {
        case .flex:
            return self.rawValue
        case .fixed:
            return self.rawValue
        case .none:
            return nil
        }
    }
}
