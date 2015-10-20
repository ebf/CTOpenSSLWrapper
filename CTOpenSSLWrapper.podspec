Pod::Spec.new do |spec|
  spec.name          = 'CTOpenSSLWrapper'
  spec.version       = '1.3.1'
  spec.license       = 'MIT'
  spec.source        = { :git => 'https://github.com/ebf/CTOpenSSLWrapper.git', :tag => spec.version.to_s }
  spec.source_files  = 'CTOpenSSLWrapper/*.{h,m}', 'CTOpenSSLWrapper/Framework Additions/**/**/*.{h,m}', 'CTOpenSSLWrapper/**/*.{h,m}'
  spec.frameworks    = 'Foundation'
  spec.requires_arc  = true
  spec.homepage      = 'https://github.com/ebf/CTOpenSSLWrapper'
  spec.summary       = 'Objc OpenSSL wrapper.'
  spec.author        = { 'Oliver Letterer' => 'oliver.letterer@gmail.com' }

  spec.platform      = :ios, '7.0'

  spec.vendored_frameworks = 'openssl.framework'
end
