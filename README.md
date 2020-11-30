![Swift Logo](https://github.com/EOSIO/eosio-swift-vault/raw/master/img/swift-logo.png)
# EOSIO SDK for Swift: Vault

[![Software License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](https://github.com/EOSIO/eosio-swift/blob/master/LICENSE)
[![Swift 5.0](https://img.shields.io/badge/Language-Swift_5.0-orange.svg)](https://swift.org)
![](https://img.shields.io/badge/Deployment%20Target-iOS%2011.3-blue.svg)

EOSIO SDK for Swift: Vault consists of two main components; _Vault_ and _Vault Signature Provider_.

_Vault_ is a utility library for working with public/private keys and signing with Apple's Keychain and Secure Enclave. It exposes key generation, management and signing functions that can be called directly.

_Vault Signature Provider_ is a pluggable signature provider for [EOSIO SDK for Swift](https://github.com/EOSIO/eosio-swift) that depends on _Vault_. It allows for signing transactions using keys stored in Keychain or the device's Secure Enclave.

*All product and company names are trademarks™ or registered® trademarks of their respective holders. Use of them does not imply any affiliation with or endorsement by them.*

## Contents

- [About Signature Providers](#about-signature-providers)
- [Prerequisites](#prerequisites)
- [Swift Package Manager Installation](#swift-package-manager-installation)
- [Cocoapods Installation](#cocoapods-installation)
- [Additional Installation Steps](#additional-installation-steps)
- [Vault Signature Provider Usage](#vault-signature-provider-usage)
- [Vault Signature Provider Library Methods](#vault-signature-provider-library-methods)
- [Vault Usage](#vault-usage)
- [EosioVault](#eosiovault)
- [Key Generation](#key-generation)
- [Signing](#signing)
- [Key Management](#key-management)
- [Documentation](#documentation)
- [Want to Help?](#want-to-help)
- [License & Legal](#license)

## About Signature Providers

The Signature Provider abstraction is arguably the most useful of all of the [EOSIO SDK for Swift](https://github.com/EOSIO/eosio-swift) providers. It is responsible for:

* finding out what keys are available for signing (`getAvailableKeys`), and
* requesting and obtaining transaction signatures with a subset of the available keys (`signTransaction`).

By simply switching out the signature provider on a transaction, signature requests can be routed any number of ways. Need a signature from keys in the platform's Keychain or Secure Enclave? [Configure the `EosioTransaction`](https://github.com/EOSIO/eosio-swift#basic-usage) with this signature provider. Need software signing? Take a look at the [Softkey Signature Provider](https://github.com/EOSIO/eosio-swift/blob/master/Sources/EosioSwiftSoftkeySignatureProvider/EosioSoftkeySignatureProvider.swift) component of [EOSIO SDK for Swift](https://github.com/EOSIO/eosio-swift).

All signature providers must conform to the [EosioSignatureProviderProtocol](https://github.com/EOSIO/eosio-swift/blob/master/Sources/EosioSwift/EosioSignatureProviderProtocol/EosioSignatureProviderProtocol.swift) Protocol.

## Prerequisites

* Xcode 11 or higher
* CocoaPods 1.9.3 or higher
* Swift Package Manager 5.2 or higher
* For iOS, iOS 12.0+

## Swift Package Manager Installation

If you are using Vault as part of Vault Signature Provider, Vault will be installed automatically as a dependency.

If you wish to use Vault Signature Provider, add the `EosioSwiftVaultSignatureProvider` product from `https://github.com/EOSIO/eosio-swift-vault` to your application dependencies.

Or to include it into a library, add the following to your `Package.swift` definition:

```swift
// swift-tools-version:5.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "MyName",
    platforms: [
        .iOS(.v12)
    ],
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "MyLibrary",
            targets: ["MyLibrary"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(name: "EosioSwiftVault", url: "https://github.com/EOSIO/eosio-swift-vault", from: "1.0.0"))
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "MyLibrary",
            dependencies: [
                .product(name: "EosioSwiftVaultSignatureProvider", package: "EosioSwiftVault")
        ]),
        .testTarget(
            name: "MyLibraryTests",
            dependencies: ["MyLibrary"]),
    ]
)
```
If you only want the Vault component, you can substitute `EosioSwiftVault` for the `EosioSwiftVaultSignatureProvider` in the product name definition in your dependencies.

## CocoaPods Installation

Vault and Vault Signature provider are separated as subspecs in Cocoapods.  If you install the entire pod from EOSIO SDK for Swift: Vault you will get both the Vault Signature Provider and Vault.  Vault will be installed automatically as a dependency.  To do this, add the following to your [Podfile](https://guides.cocoapods.org/syntax/podfile.html):

```ruby
use_frameworks!

target "Your Target" do
  pod "EosioSwiftVault", "~> 1.0.0"
end
```

Then run `pod install`.

If you wish to use only Vault directly, add the following pods to your [Podfile](https://guides.cocoapods.org/syntax/podfile.html):

```ruby
use_frameworks!

target "Your Target" do
  pod "EosioSwiftVault/Vault", "~> 1.0.0"
end
```

Then run `pod install`.

## Additional Installation Steps

If you are using the Vault Signature Provider component there are some additional steps to follow after integrating with your package manager.

You must also configure your application as a member of an App Group. See [Apple's documentation here](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps#2974917) for instructions on enabling and configuring the App Group Capability in Xcode.

Now Vault Signature Provider is ready for use within EOSIO SDK for Swift according to the [EOSIO SDK for Swift Basic Usage instructions](https://github.com/EOSIO/eosio-swift/tree/master#basic-usage).

## Vault Signature Provider Usage

Generally, signature providers are called by [`EosioTransaction`](https://github.com/EOSIO/eosio-swift/blob/master/Sources/EosioSwift/EosioTransaction/EosioTransaction.swift) during signing. ([See an example here.](https://github.com/EOSIO/eosio-swift#basic-usage)) If you find, however, that you need to get available keys or request signing directly, this library can be invoked as follows:

```swift
let signProvider = try? EosioVaultSignatureProvider(accessGroup: "YOUR_ACCESS_GROUP")
let publicKeysArray = signProvider?.getAvailableKeys() // Returns the public keys.
```

_[Learn more about Access Groups here.](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps)_

To sign an [`EosioTransaction`](https://github.com/EOSIO/eosio-swift/blob/master/Sources/EosioSwift/EosioTransaction/EosioTransaction.swift), create an [`EosioTransactionSignatureRequest`](https://github.com/EOSIO/eosio-swift/blob/master/Sources/EosioSwift/EosioSignatureProviderProtocol/EosioSignatureProviderProtocol.swift) object and call the `EosioVaultSignatureProvider.signTransaction(request:completion:)` method with the request:

```swift
var signRequest = EosioTransactionSignatureRequest()
signRequest.serializedTransaction = serializedTransaction
signRequest.publicKeys = publicKeys
signRequest.chainId = chainId

signProvider.signTransaction(request: signRequest) { (response) in
    ...
}
```

## Vault Signature Provider Library Methods

This library is an implementation of [`EosioSignatureProviderProtocol`](https://github.com/EOSIO/eosio-swift/blob/master/Sources/EosioSwift/EosioSignatureProviderProtocol/EosioSignatureProviderProtocol.swift). It implements the following protocol methods:

* `EosioVaultSignatureProvider.signTransaction(request:completion:)` signs an [`EosioTransaction`](https://github.com/EOSIO/eosio-swift/blob/master/Sources/EosioSwift/EosioTransaction/EosioTransaction.swift).
* `EosioVaultSignatureProvider.getAvailableKeys(...)` returns an array containing the public keys associated with the private keys that the object is initialized with.

To initialize the implementation:

* `EosioVaultSignatureProvider.init(accessGroup:requireBio:)` initializes the signature provider.
  * `accessGroup`: [Learn more about Access Groups here.](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps)
  * `requireBio`: Defaults to `false`. Some keys may require biometric authentication no matter what this flag is set to. For keys that do not require biometric authentication themselves, this flag can force the bio check.

Other Keychain and/or Secure Enclave functionality can be accessed by calling methods directly on the Vault component, which is included with Vault Signature Provider as a dependency.

## Vault Usage

If you wish, Vault can be worked with directly, rather than through Vault Signature Provider.  The following sections describe the main components of Vault and how to interact with them.

## EosioVault

The primary class for interacting with the EOSIO SDK for Swift: Vault is `EosioVault`. An instance of `EosioVault` is instantiated with an `accessGroup` as follows:

```swift
import EosioSwiftVault

let vault = EosioVault(accessGroup: accessGroup)
```
The `accessGroup` is an [App Group Identifier](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups) or a [Keychain Access Group Identifier](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups) that allows the keys to be shared between different apps and app extensions in the same developer account.

## Key Generation

The Vault library exposes functions to generate new EOSIO keys. New keys can either be generated and stored in the device's [Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave) or the Keychain. **Note:** If the key is stored in Secure Enclave, it is not possible to directly access or export the private key.

**Important:** Currently key metadata must conform to the rules for conversion by [JSONSerialization](https://developer.apple.com/documentation/foundation/jsonserialization).  Failure to do so will result in application errors.

To create a key in Secure Enclave:

```swift
let newKey = try vault.newVaultKey(secureEnclave: true, protection: .whenUnlockedThisDeviceOnly, bioFactor: .none, metadata: [String: Any])
```
or use the convenience function:

```swift
let newKey = try vault.newSecureEnclaveKey(bioFactor: .none, metadata: [String: Any])
```

To create a key in Keychain:

```swift
let newKey = try vault.newVaultKey(secureEnclave: false, protection: .whenUnlockedThisDeviceOnly, bioFactor: .none, metadata: [String: Any])
```

The `bioFactor` is the type of biometric security that will be required by the keychain to sign messages with this key. The `metadata` can be any data you want to associate with this key. `protection` is the accessibility to use for the key.

Each of the above functions will return an `EosioVault.VaultKey`. To access the EOSIO public and private keys:

```swift
let publicKey = newKey.eosioPublicKey
let privateKey = newKey.eosioPrivateKey
```
For Secure Enclave keys the `eosioPrivateKey` is `nil` as it cannot be accessed.


## Signing

In most cases, signing is handled via the Vault Signature Provider component. However, a message can also be signed directly with an instance of `EosioVault`:

```swift
let signature = vault.sign(message: message, eosioPublicKey: publicKey, requireBio: true) { (signature, error) in
	// handle signature or error
}
```

Biometric requirements can be set as part of the key, itself, or enforced as a separate software check. The `requireBio` flag will require biometric identification to sign with this key, even if the key does not require it. However, setting the `requireBio` to `false` will **not** disable biometric identification if required by the key.

## Key Management

The Vault library exposes functions to get existing keys, add external keys, delete keys and modify metadata for existing keys.

To get a single VaultKey for an EOSIO public key:

```swift
let key = try getVaultKey(eosioPublicKey: publicKey)
```

To get an array of all keys:

```swift
let keys = try getAllVaultKeys() 
```

To add an external key to the Keychain with the private key:

```swift
try vault.addExternal(eosioPrivateKey: privateKey, metadata: [String: Any]) 
```
To delete a key:

```swift
try deleteKey(eosioPublicKey: publicKey)
```
To update an existing key, update the metadata property and then:

```swift
update(key: myKey)
```

## Documentation

Please refer to the generated code documentation at https://eosio.github.io/eosio-swift-vault or by cloning this repo.  Vault documentation can be referenced by opening the `docs/EosioSwiftVault/index.html` file in your browser.  Vault Signature Provider documentation can be found at `docs/EosioSwiftVaultSignatureProvider/index.html`.  Documentation can be regenerated or updated by running the `update_documentation.sh` script in the repo.

## Want to help?

Interested in contributing? That's awesome! Here are some [Contribution Guidelines](https://github.com/EOSIO/eosio-swift-vault/blob/master/CONTRIBUTING.md) and the [Code of Conduct](https://github.com/EOSIO/eosio-swift-vault/blob/master/CONTRIBUTING.md#conduct).

## License

[MIT](https://github.com/EOSIO/eosio-swift-vault/blob/master/LICENSE)

## Important

See LICENSE for copyright and license terms.  Block.one makes its contribution on a voluntary basis as a member of the EOSIO community and is not responsible for ensuring the overall performance of the software or any related applications.  We make no representation, warranty, guarantee or undertaking in respect of the software or any related documentation, whether expressed or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall we be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or documentation or the use or other dealings in the software or documentation. Any test results or performance figures are indicative and will not reflect performance under all conditions.  Any reference to any third party or third-party product, service or other resource is not an endorsement or recommendation by Block.one.  We are not responsible, and disclaim any and all responsibility and liability, for your use of or reliance on any of these resources. Third-party resources may be updated, changed or terminated at any time, so the information here may be out of date or inaccurate.  Any person using or offering this software in connection with providing software, goods or services to third parties shall advise such third parties of these license terms, disclaimers and exclusions of liability.  Block.one, EOSIO, EOSIO Labs, EOS, the heptahedron and associated logos are trademarks of Block.one.

Wallets and related components are complex software that require the highest levels of security.  If incorrectly built or used, they may compromise users’ private keys and digital assets. Wallet applications and related components should undergo thorough security evaluations before being used.  Only experienced developers should work with this software.
