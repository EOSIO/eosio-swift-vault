using_local_pods = ENV['USE_LOCAL_PODS'] == 'true' || false

platform :ios, '11.3'

# ignore all warnings from all pods
inhibit_all_warnings!

if using_local_pods
  # Pull pods from sibling directories if using local pods
  target 'EosioSwiftVault' do
    use_frameworks!

    pod 'EosioSwift', :path => '../eosio-swift'
    pod 'EosioSwiftEcc', :path => '../eosio-swift-ecc'
    pod 'SwiftLint'

    target 'EosioSwiftVaultTests' do
      # inherit! :search_paths
    end
  end
else
  # Pull pods from sources above if not using local pods
  target 'EosioSwiftVault' do
    use_frameworks!

    pod 'EosioSwift', '~> 0.3.0'
    pod 'EosioSwiftEcc', '~> 0.3.0'
    pod 'SwiftLint'

    target 'EosioSwiftVaultTests' do
      use_frameworks!

      pod 'EosioSwift', '~> 0.3.0'
      pod 'EosioSwiftEcc', '~> 0.3.0'
      pod 'SwiftLint'
    end
  end
end
