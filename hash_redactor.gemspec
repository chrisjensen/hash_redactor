# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'hash_redactor/version'

Gem::Specification.new do |spec|
  spec.name          = "hash_redactor"
  spec.version       = HashRedactor::VERSION
  spec.authors       = ["Chris Jensen"]
  spec.email         = ["chris@broadthought.co"]

  spec.summary       = %q{Redact specified values in a hash}
  spec.description   = %q{Removes, digests or encrypts selected values in a ruby hash}
  spec.homepage      = "https://github.com/chrisjensen/hash_redactor"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency 'attr_encrypted', '~> 3.0.0'

  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency 'rspec', '~> 2.14'

  spec.add_development_dependency("codeclimate-test-reporter")
end
