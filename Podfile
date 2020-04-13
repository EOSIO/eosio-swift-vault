using_local_pods = ENV['USE_LOCAL_PODS'] == 'true' || false

platform :ios, '11.3'

# ignore all warnings from all pods
inhibit_all_warnings!

if using_local_pods
  # Pull pods from sibling directories if using local pods
  target 'EosioSwiftVaultSignatureProvider' do
    use_frameworks!

    pod 'EosioSwift', :path => '../eosio-swift'
    pod 'EosioSwiftEcc', :path => '../eosio-swift-ecc'
    pod 'EosioSwiftVault', :path => '../eosio-swift-vault'
    pod 'SwiftLint'

    target 'EosioSwiftVaultSignatureProviderTests' do
      inherit! :search_paths
      pod 'EosioSwift', :path => '../eosio-swift'
      pod 'EosioSwiftEcc', :path => '../eosio-swift-ecc'
      pod 'EosioSwiftVault', :path => '../eosio-swift-vault'
    end
  end
else
  # Pull pods from sources above if not using local pods
  target 'EosioSwiftVaultSignatureProvider' do
    use_frameworks!

    pod 'EosioSwift', '~> 0.4.0'
    pod 'EosioSwiftEcc', '~> 0.4.0'
    pod 'EosioSwiftVault', '~> 0.4.0'
    pod 'SwiftLint'

    target 'EosioSwiftVaultSignatureProviderTests' do
      use_frameworks!
      inherit! :search_paths
      pod 'EosioSwift', '~> 0.4.0'
      pod 'EosioSwiftEcc', '~> 0.4.0'
      pod 'EosioSwiftVault', '~> 0.4.0'
    end
  end
end
