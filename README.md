# EOSIO SDK for Swift: Vault ![EOSIO Alpha](https://img.shields.io/badge/EOSIO-Alpha-blue.svg)
[![Software License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](https://github.com/EOSIO/eosio-swift/blob/master/LICENSE)
[![Swift 4.2](https://img.shields.io/badge/Language-Swift_4.2-orange.svg)](https://swift.org)
![](https://img.shields.io/badge/Deployment%20Target-iOS%2011.3-blue.svg)

EOSIO SDK for Swift: Vault is a utility library for working with public/private keys and signing with Apple's Keychain and Secure Enclave.

Used primarily as a dependency of the [EOSIO SDK for Swift: Vault Signature Provider](https://github.com/EOSIO/eosio-swift-vault-signature-provider), Vault also exposes key and signing utilities that can be called directly.

*All product and company names are trademarks™ or registered® trademarks of their respective holders. Use of them does not imply any affiliation with or endorsement by them.*

## Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Direct Usage](#direct-usage)
- [Library Methods](#library-methods)
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
  pod "EosioSwiftVault", "~> 0.0.1"
end
```

Then run `pod install`.

## Direct Usage

TBD

## Library Methods

TBD

## Want to help?

Interested in contributing? That's awesome! Here are some [Contribution Guidelines](./CONTRIBUTING.md) and the [Code of Conduct](./CONTRIBUTING.md#conduct).

## License

[MIT](./LICENSE)

## Important

See LICENSE for copyright and license terms.  Block.one makes its contribution on a voluntary basis as a member of the EOSIO community and is not responsible for ensuring the overall performance of the software or any related applications.  We make no representation, warranty, guarantee or undertaking in respect of the software or any related documentation, whether expressed or implied, including but not limited to the warranties or merchantability, fitness for a particular purpose and noninfringement. In no event shall we be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or documentation or the use or other dealings in the software or documentation.  Any test results or performance figures are indicative and will not reflect performance under all conditions.  Any reference to any third party or third-party product, service or other resource is not an endorsement or recommendation by Block.one.  We are not responsible, and disclaim any and all responsibility and liability, for your use of or reliance on any of these resources. Third-party resources may be updated, changed or terminated at any time, so the information here may be out of date or inaccurate.

Wallets and related components are complex software that require the highest levels of security.  If incorrectly built or used, they may compromise users’ private keys and digital assets. Wallet applications and related components should undergo thorough security evaluations before being used.  Only experienced developers should work with this software.
