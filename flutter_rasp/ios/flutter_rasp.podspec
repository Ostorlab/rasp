Pod::Spec.new do |s|
  s.name = 'flutter_rasp'
  s.version = '0.0.1'
  s.summary = 'Private runtime application self-protection SDK.'
  s.description = 'Proprietary Flutter adapter for the iOS RASP core.'
  s.homepage = 'https://github.com/Ostorlab/rasp'
  s.license = { :type => 'Proprietary', :file => '../LICENSE' }
  s.author = { 'Ostorlab' => 'support@ostorlab.co' }
  s.source = { :path => '.' }
  s.source_files = 'Classes/**/*.swift'
  s.dependency 'Flutter'
  s.platform = :ios, '14.0'
  s.swift_version = '5.9'
  s.frameworks = 'Security', 'CryptoKit', 'DeviceCheck', 'UIKit'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
