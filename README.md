![Swift Logo](https://github.com/EOSIO/eosio-swift-vault/raw/master/img/swift-logo.png)
# EOSIO SDK for Swift: Vault ![EOSIO Alpha](https://img.shields.io/badge/EOSIO-Alpha-blue.svg)

[![Software License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](https://github.com/EOSIO/eosio-swift/blob/master/LICENSE)
[![Swift 4.2](https://img.shields.io/badge/Language-Swift_4.2-orange.svg)](https://swift.org)
![](https://img.shields.io/badge/Deployment%20Target-iOS%2011.3-blue.svg)

EOSIO SDK for Swift: Vault is a utility library for working with public/private keys and signing with Apple's Keychain and Secure Enclave.

The Vault library is a required dependency of the [EOSIO SDK for Swift: Vault Signature Provider](https://github.com/EOSIO/eosio-swift-vault-signature-provider). It additionally provides key generation, management and signing functions that can be called directly.
*All product and company names are trademarks™ or registered® trademarks of their respective holders. Use of them does not imply any affiliation with or endorsement by them.*

## Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [EosioVault](#eosiovault)
- [Key Generation](#key-generation)
- [Signing](#signing)
- [Key Management](#key-management)
- [Documentation](#documentation)
- [Want to Help?](#want-to-help)
- [License & Legal](#license)

## Prerequisites

* Xcode 10 or higher
* CocoaPods 1.5.3 or higher
* For iOS, iOS 11.3+

## Installation

If you are using Vault as part of the [EOSIO SDK for Swift: Vault Signature Provider](https://github.com/EOSIO/eosio-swift-vault-signature-provider) pod, Vault will be installed automatically as a dependency.

If you wish to use Vault directly, add the following pods to your [Podfile](https://guides.cocoapods.org/syntax/podfile.html):

```ruby
use_frameworks!

target "Your Target" do
  pod "EosioSwiftVault", "~> 0.1.3"
end
```

Then run `pod install`.

## EosioVault

The primary class for interacting with the EOSIO SDK for Swift: Vault is `EosioVault`. A instance of `EosioVault` is instantiated with an `accessGroup` as follows:

```swift
import EosioSwiftVault

let vault = EosioVault(accessGroup: accessGroup)
```
The `accessGroup` is a [App Group Identifier](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups) or a [Keychain Access Group Identifier](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups) that allows the keys to be shared between different apps and app extensions in the same developer account.

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

The `bioFactor` is the type of biometric security that will be required by the keychain to sign messages with this key. The `metadata` can be any data you want to associate with this key.

`protection` is the accessibility to use the for key.

Each of the above functions will return an `EosioVault.VaultKey`. To access the EOSIO public and private keys:

```swift
let publicKey = newKey.eosioPublicKey
let privateKey = newKey.eosioPrivateKey
```
For Secure Enclave keys the `eosioPrivateKey` is `nil` as it cannot be accessed.


## Signing

In most cases, signing is handled via the [EOSIO SDK for Swift: Vault Signature Provider](https://github.com/EOSIO/eosio-swift-vault-signature-provider). However, a message can also be signed directly with an instance of `EosioVault`:

```swift
let signature = vault.sign(message: message, eosioPublicKey: publicKey, requireBio: true) { (signature, error) in
	// handle signature or error
}
```

Biometric requirements can set as part of the key, itself, or enforced as a separate software check. The `requireBio` flag will require biometric identification to sign with this key, even if the key does not require it. However, setting the `requireBio` to `false` will **not** disable biometric identification if required by the key.

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

Please refer to the generated code documentation at https://eosio.github.io/eosio-swift-vault or by cloning this repo and opening the `docs/index.html` file in your browser.

## Want to help?

Interested in contributing? That's awesome! Here are some [Contribution Guidelines](https://github.com/EOSIO/eosio-swift-vault/blob/master/CONTRIBUTING.md) and the [Code of Conduct](https://github.com/EOSIO/eosio-swift-vault/blob/master/CONTRIBUTING.md#conduct).

## License

[MIT](https://github.com/EOSIO/eosio-swift-vault/blob/master/LICENSE)

## Important

See LICENSE for copyright and license terms.  Block.one makes its contribution on a voluntary basis as a member of the EOSIO community and is not responsible for ensuring the overall performance of the software or any related applications.  We make no representation, warranty, guarantee or undertaking in respect of the software or any related documentation, whether expressed or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall we be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or documentation or the use or other dealings in the software or documentation. Any test results or performance figures are indicative and will not reflect performance under all conditions.  Any reference to any third party or third-party product, service or other resource is not an endorsement or recommendation by Block.one.  We are not responsible, and disclaim any and all responsibility and liability, for your use of or reliance on any of these resources. Third-party resources may be updated, changed or terminated at any time, so the information here may be out of date or inaccurate.  Any person using or offering this software in connection with providing software, goods or services to third parties shall advise such third parties of these license terms, disclaimers and exclusions of liability.  Block.one, EOSIO, EOSIO Labs, EOS, the heptahedron and associated logos are trademarks of Block.one.

Wallets and related components are complex software that require the highest levels of security.  If incorrectly built or used, they may compromise users’ private keys and digital assets. Wallet applications and related components should undergo thorough security evaluations before being used.  Only experienced developers should work with this software.
