#
# Be sure to run `pod lib lint EosioSwiftVault.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'EosioSwiftVault'
  s.version          = '0.1.2'
  s.summary          = 'Keychain and Secure Enclave functions for EOSIO.'
  s.homepage         = 'https://github.com/EOSIO/eosio-swift-vault'
  s.license          = { :type => 'MIT', :text => <<-LICENSE
                           Copyright (c) 2017-2019 block.one and its contributors.  All rights reserved.
                         LICENSE
                       }
  s.author           = { 'Todd Bowden' => 'todd.bowden@block.one' }
  s.source           = { :git => 'https://github.com/EOSIO/eosio-swift-vault.git', :tag => "v" + s.version.to_s }

  s.swift_version         = '4.2'
  s.ios.deployment_target = '11.3'

  s.source_files = 'EosioSwiftVault/**/*.swift'

  s.pod_target_xcconfig = {
    'CLANG_ALLOW_NON_MODULAR_INCLUDES_IN_FRAMEWORK_MODULES' => 'YES',
    'CLANG_ENABLE_MODULES' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule',
    'ENABLE_BITCODE' => 'YES' }

  s.ios.dependency 'EosioSwift', '~> 0.1.2'
  s.ios.dependency 'EosioSwiftEcc', '~> 0.1.2'
end
