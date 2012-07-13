# -*- encoding: utf-8 -*-
require File.expand_path('../lib/vpk/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["kimoto"]
  gem.email         = ["sub+peerler@gmail.com"]
  gem.description   = %q{VPK File Format Parser (extract and archive)}
  gem.summary       = %q{VPK File Format Parser (extract and archive)}
  gem.homepage      = "http://github.com/kimoto/vpk"

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "vpk"
  gem.require_paths = ["lib"]
  gem.version       = VPK::VERSION
end
