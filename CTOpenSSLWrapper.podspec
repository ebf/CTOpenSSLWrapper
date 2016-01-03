Pod::Spec.new do |s|
  s.name          = 'CTOpenSSLWrapper'
  s.version       = '1.5.0'
  s.license       = 'MIT'
  s.source        = { :git => 'https://github.com/ebf/CTOpenSSLWrapper.git', :tag => s.version.to_s }
  s.frameworks    = 'Foundation'
  s.requires_arc  = true
  s.homepage      = 'https://github.com/ebf/CTOpenSSLWrapper'
  s.summary       = 'Objc OpenSSL wrapper.'
  s.author        = { 'Oliver Letterer' => 'oliver.letterer@gmail.com' }

  s.platforms     = { :ios => '8.0', :tvos => '9.0' }

  s.ios.vendored_frameworks  = 'ios/openssl.framework'
  s.tvos.vendored_frameworks = 'tvos/openssl.framework'

  s.source_files  = 'CTOpenSSLWrapper/*.{h,m}', 'CTOpenSSLWrapper/Framework Additions/**/**/*.{h,m}', 'CTOpenSSLWrapper/**/*.{h,m}'
end
