require 'json'

package = JSON.parse(File.read(File.join(__dir__, 'package.json')))

Pod::Spec.new do |s|
  s.name           = 'ChainberryTrustWalletCoreModule'
  s.version        = package['version']
  s.summary        = package['description']
  s.description    = s.summary
  s.homepage       = 'https://github.com/Chainberry-com/trust-wallet-core'
  s.license        = package['license']
  s.author         = 'Chainberry'
  s.platform       = :ios, '15.1'
  s.source         = { git: 'git@github.com:Chainberry-com/trust-wallet-core.git', tag: "v#{package['version']}" }
  s.static_framework = true

  s.source_files         = 'ios/**/*.{h,m,mm,swift}'
  s.exclude_files        = 'ios/ConformanceTests/**'

  s.dependency 'ExpoModulesCore'
  s.dependency 'TrustWalletCore', '4.1.19'

  s.test_spec 'ConformanceTests' do |ts|
    ts.source_files = 'ios/ConformanceTests/*.swift'
    ts.dependency 'TrustWalletCore', '4.1.19'
    ts.resources = ['conformance/signing-vectors.json', 'conformance/address-derivation-vectors.json']
  end
end
