Pod::Spec.new do |spec|
  spec.name          = 'CTOpenSSLWrapper'
  spec.version       = '1.0.0'
  spec.platform      = :ios, '6.0'
  spec.license       = 'MIT'
  spec.source        = { :git => 'https://github.com/ebf/CTOpenSSLWrapper.git', :tag => spec.version.to_s }
  spec.source_files  = 'CTOpenSSLWrapper/CTOpenSSLWrapper/*.{h,m}', 'CTOpenSSLWrapper/CTOpenSSLWrapper/Framework Additions/**/**/*.{h,m}', 'CTOpenSSLWrapper/CTOpenSSLWrapper/**/*.{h,m}'
  spec.frameworks    = 'Foundation'
  spec.requires_arc  = true
  spec.homepage      = 'https://github.com/ebf/CTOpenSSLWrapper'
  spec.summary       = 'Objc OpenSSL wrapper.'
  spec.author        = { 'Oliver Letterer' => 'oliver.letterer@gmail.com' }

  spec.xcconfig       = { 'LIBRARY_SEARCH_PATHS' => '"$(PODS_ROOT)/CTOpenSSLWrapper/CTOpenSSLWrapper"', 
                          'USER_HEADER_SEARCH_PATHS' => '"$(inherited) $(PODS_ROOT)/CTOpenSSLWrapper/include"' }

  spec.dependency     'OpenSSL', '1.0.1c'

  spec.prefix_header_contents = <<-EOS
#ifdef __OBJC__
    #import <Foundation/Foundation.h>
#endif
EOS
end
