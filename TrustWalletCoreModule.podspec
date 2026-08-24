require 'json'

package = JSON.parse(File.read(File.join(__dir__, 'package.json')))

Pod::Spec.new do |s|
  s.name           = 'TrustWalletCoreModule'
  s.version        = package['version']
  s.summary        = package['description']
  s.description    = s.summary
  s.homepage       = 'https://github.com/Chainberry-com/trust-wallet-core'
  s.license        = package['license']
  s.author         = 'Chainberry'
  s.platform       = :ios, '16.0'
  s.source         = { git: 'git@github.com:Chainberry-com/trust-wallet-core.git', tag: "v#{package['version']}" }
  s.static_framework = true

  s.source_files = 'ios/**/*.{h,m,mm,swift}'

  s.dependency 'ExpoModulesCore'
  s.dependency 'TrustWalletCore', '4.1.19'
end
