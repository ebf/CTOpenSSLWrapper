Pod::Spec.new do |s|
  s.name          = 'CTOpenSSLWrapper'
  s.version       = '1.4.2'
  s.license       = 'MIT'
  s.source        = { :git => 'https://github.com/ebf/CTOpenSSLWrapper.git', :tag => s.version.to_s }
  s.frameworks    = 'Foundation'
  s.requires_arc  = true
  s.homepage      = 'https://github.com/ebf/CTOpenSSLWrapper'
  s.summary       = 'Objc OpenSSL wrapper.'
  s.author        = { 'Oliver Letterer' => 'oliver.letterer@gmail.com' }

  s.platforms     = { :ios => '8.0', :osx => '10.11', :tvos => '9.0' }
  s.default_subspec = 'CTOpenSSLWrapper_iOS'

  s.subspec 'CTOpenSSLWrapper_iOS' do |ss|
    ss.source_files  = 'CTOpenSSLWrapper/*.{h,m}', 'CTOpenSSLWrapper/Framework Additions/**/**/*.{h,m}', 'CTOpenSSLWrapper/**/*.{h,m}'
    ss.dependency "CTOpenSSLWrapper/OpenSSL_iOS"
  end

  s.subspec 'CTOpenSSLWrapper_tvOS' do |ss|
    ss.source_files  = 'CTOpenSSLWrapper/*.{h,m}', 'CTOpenSSLWrapper/Framework Additions/**/**/*.{h,m}', 'CTOpenSSLWrapper/**/*.{h,m}'
    ss.dependency "CTOpenSSLWrapper/OpenSSL_tvOS"
  end

  s.subspec 'CTOpenSSLWrapper_osx' do |ss|
    ss.source_files  = 'CTOpenSSLWrapper/*.{h,m}', 'CTOpenSSLWrapper/Framework Additions/**/**/*.{h,m}', 'CTOpenSSLWrapper/**/*.{h,m}'
    ss.dependency "CTOpenSSLWrapper/OpenSSL_osx"
  end

  s.subspec "OpenSSL_iOS" do |ss|
    ss.source_files        = 'include/openssl/*.h'
    ss.public_header_files = 'include/openssl/*.h'
    ss.header_dir          = 'openssl'

    ss.ios.vendored_libraries  = 'lib/libcrypto_iOS.a', 'lib/libssl_iOS.a'
    ss.osx.vendored_libraries  = 'lib/libcrypto_Mac.a', 'lib/libssl_Mac.a'
    ss.tvos.vendored_libraries = 'lib/libcrypto_tvOS.a', 'lib/libssl_tvOS.a'
  end

  s.subspec "OpenSSL_tvOS" do |ss|
    ss.source_files        = 'include/openssl/*.h'
    ss.public_header_files = 'include/openssl/*.h'
    ss.header_dir          = 'openssl'

    ss.ios.vendored_libraries  = 'lib/libcrypto_iOS.a', 'lib/libssl_iOS.a'
    ss.osx.vendored_libraries  = 'lib/libcrypto_Mac.a', 'lib/libssl_Mac.a'
    ss.tvos.vendored_libraries = 'lib/libcrypto_tvOS.a', 'lib/libssl_tvOS.a'
  end

  s.subspec "OpenSSL_osx" do |ss|
    ss.source_files        = 'include/openssl/*.h'
    ss.public_header_files = 'include/openssl/*.h'
    ss.header_dir          = 'openssl'

    ss.ios.vendored_libraries  = 'lib/libcrypto_iOS.a', 'lib/libssl_iOS.a'
    ss.osx.vendored_libraries  = 'lib/libcrypto_Mac.a', 'lib/libssl_Mac.a'
    ss.tvos.vendored_libraries = 'lib/libcrypto_tvOS.a', 'lib/libssl_tvOS.a'
  end
end
