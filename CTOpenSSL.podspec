Pod::Spec.new do |s|
  s.name          = 'CTOpenSSL'
  s.version       = '1.4.2'
  s.license       = 'MIT'
  s.source        = { :git => 'https://github.com/ebf/CTOpenSSLWrapper.git', :tag => s.version.to_s }
  s.frameworks    = 'Foundation'
  s.requires_arc  = true
  s.homepage      = 'https://github.com/ebf/CTOpenSSLWrapper'
  s.summary       = 'Objc OpenSSL wrapper.'
  s.author        = { 'Oliver Letterer' => 'oliver.letterer@gmail.com' }

  s.platforms     = { :ios => '8.0', :osx => '10.11', :tvos => '9.0' }

  s.source_files        = 'include/openssl/*.h', 'lib/Dummy.m'
  s.public_header_files = 'include/openssl/*.h'
  s.module_name         = 'openssl'

  s.ios.vendored_libraries  = 'lib/libcrypto_iOS.a', 'lib/libssl_iOS.a'
  s.osx.vendored_libraries  = 'lib/libcrypto_Mac.a', 'lib/libssl_Mac.a'
  s.tvos.vendored_libraries = 'lib/libcrypto_tvOS.a', 'lib/libssl_tvOS.a'
end
