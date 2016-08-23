# hash_redactor #

## 0.4.0 ##
* Added: Allow mode to be strings instead of symbols (@chrisjensen)

## 0.3.1 ##
* Fixed: nil values caused encryption to fail (@chrisjensen)
* Added: digest_empty to improve performance on empty strings (@chrisjensen)
* Changed: Improved performance when encrypt is passed an empty string (@chrisjensen)

##0.3.0 ##
* Added: Whitelist mode (@chrisjensen)
* Fixed: redact + decrypt loop specs should check result is not empty (@chrisjensen)

##0.2.1 ##
* Fixed: Add support for string keys (@chrisjensen)

##0.2.0 ##
* Changed: encrypted_key and encrypted_attr_iv are removed during decryption (@chrisjensen)

##0.1.1 ##
* Fixed: Do not specify bundler version in gemspec (@chrisjensen)