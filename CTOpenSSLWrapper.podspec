Pod::Spec.new do |spec|
  spec.name          = 'CTOpenSSLWrapper'
  spec.version       = '1.3.1'
  spec.license       = 'MIT'
  spec.source        = { :git => 'https://github.com/ebf/CTOpenSSLWrapper.git', :tag => spec.version.to_s }
  spec.frameworks    = 'Foundation'
  spec.requires_arc  = true
  spec.homepage      = 'https://github.com/ebf/CTOpenSSLWrapper'
  spec.summary       = 'Objc OpenSSL wrapper.'
  spec.author        = { 'Oliver Letterer' => 'oliver.letterer@gmail.com' }

  spec.platforms     = { :ios => '8.0', :osx => '10.11', :tvos => '9.0' }

  spec.default_subspec = 'CTOpenSSLWrapper'
  spec.subspec 'CTOpenSSLWrapper' do |subspec|
    subspec.source_files  = 'CTOpenSSLWrapper/*.{h,m}', 'CTOpenSSLWrapper/Framework Additions/**/**/*.{h,m}', 'CTOpenSSLWrapper/**/*.{h,m}'
    subspec.dependency "CTOpenSSLWrapper/OpenSSL"
  end

  spec.subspec 'OpenSSL' do |subspec|
    subspec.source_files        = 'include/openssl/*.h'
    subspec.public_header_files = 'include/openssl/*.h'
    subspec.header_dir          = 'openssl'

    subspec.ios.vendored_libraries  = 'lib/libcrypto_iOS.a', 'lib/libssl_iOS.a'
    subspec.tvos.vendored_libraries = 'lib/libcrypto_tvOS.a', 'lib/libssl_tvOS.a'
    subspec.osx.vendored_libraries = 'lib/libcrypto_Mac.a', 'lib/libssl_Mac.a'
  end
end
