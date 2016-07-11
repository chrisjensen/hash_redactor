require 'attr_encrypted'

module HashRedactor
  class HashRedactor
	  def initialize(opts = {})
		@options = default_options.merge opts

		@options[:encode] = @options[:default_encoding] if @options[:encode] == true
		@options[:encode_iv] = @options[:default_encoding] if @options[:encode_iv] == true
		
		raise "unknown filter mode #{@options[:filter_mode]}" unless [:blacklist,:whitelist].include? @options[:filter_mode]
	  end
  
  	  def default_options
  	  	{
  	  	  digest_salt: 		 "",
		  encryption_key:	 nil,
		  encode:            true,
		  encode_iv:         true,
		  default_encoding:  'm',
		  filter_mode:		 :blacklist
  	  	}
  	  end
  	  
  	  def options
  	  	@options
  	  end
  
	  # Removes, digests or encrypts fields in a hash
	  # NOTE: This should NOT be used to protect password fields or similar
	  # The purpose of hashing is to reduce data to a form that can be *quickly*
	  # compared against other records without revealing the original value.
	  # To allow for this, all hashes are created using the *same salt* which is
	  # not secure enough for password protection
	  # For passwords, use BCrypt
	  def redact(data, opts = {})
	    options = @options.merge(opts)
	    
  		redact_hash = options[:redact]
  		
  		raise "Don't know what to redact. Please configure the redact hash when initializing or pass as an argument to redact." unless redact_hash && redact_hash.any?
  
		result = data.clone
  
  		# If it's blacklist mode, just go over our redact keys
  		# Otherwise, we have to go through and remove all keys that aren't :keep
  		if (options[:filter_mode] == :whitelist)
  		  keys = data.keys
		  redact_hash = whitelist_redact_hash redact_hash
  		else
  		  keys = redact_hash.keys
  		end

		keys.each do |hash_key,how|
		  how = redact_hash[hash_key] || :remove
		  
		  if data.has_key? hash_key
			case how
			  when :keep
			    nil
			  when :remove
				nil
			  when :digest
			  	digest(result, hash_key, options)
			  when :encrypt
				encrypt(result, hash_key, options)
			  else
				raise "redact called with unknown operation on #{hash_key}: #{how}"
			end

			result.delete hash_key unless how == :keep
		  end
		end
  
		result
	  end
	  
	  def digest(hash, hash_key, options)
	    dig_key = digest_key hash_key
	  
		hash[dig_key] = Digest::SHA256.base64digest(
									hash[hash_key].to_s + options[:digest_salt])
	  end
	  
	  def encrypt(hash, hash_key, options)
		raise "No encryption key specified. Please pass :encryption_key in options to new or redact" unless options[:encryption_key]
	  
		data_key = 'encrypted_' + hash_key.to_s
		iv_key = 'encrypted_' + hash_key.to_s + '_iv'
		
		if hash_key.is_a? Symbol
			data_key = data_key.to_sym
			iv_key = iv_key.to_sym
		end
	
		crypt_key = options[:encryption_key]
		iv = SecureRandom.random_bytes(12)
		
		encrypted_value = EncryptorInterface.encrypt(:data,
							 hash[hash_key], iv: iv, key: crypt_key)
		
		encrypted_value = [encrypted_value].pack(options[:encode]) if options[:encode]
		iv = [iv].pack(options[:encode_iv]) if options[:encode_iv]
	
		hash[data_key] = encrypted_value
		hash[iv_key] = iv
	  end

	  def decrypt(data, opts = {})
	    options = @options.merge opts

  		redact_hash = options[:redact]

  		raise "Don't know what to decrypt. Please configure the redact hash when initializing or pass as an argument to #decrypt." unless redact_hash && redact_hash.any?

		raise "No encryption key specified. Please pass :encryption_key in options to new or decrypt" unless options[:encryption_key]
  
		result = data.clone
  
		redact_hash.each do |hash_key,how|
		  if (how == :encrypt)
		    decrypt_value(result, hash_key, options)
		  end
		end
  
		result
	  end
	  
	  def decrypt_value(result, hash_key, options)
		data_key = 'encrypted_' + hash_key.to_s
		iv_key = 'encrypted_' + hash_key.to_s + '_iv'
		
		if hash_key.is_a? Symbol
		  data_key = data_key.to_sym
		  iv_key = iv_key.to_sym
		end

		if (result.has_key? data_key)
		  iv = result[iv_key]
		  crypt_key = options[:encryption_key]

		  encrypted_value = result[data_key]

		  # Decode if necessary
		  iv = iv.unpack(options[:encode_iv]).first if options[:encode_iv]
		  encrypted_value = encrypted_value.unpack(options[:encode]).first if options[:encode]

		  decrypted_value = EncryptorInterface.decrypt(:data, encrypted_value,
			   iv: iv, key: crypt_key)
	
		  result[hash_key] = decrypted_value
		  result.delete data_key
		  result.delete iv_key
		end
	  end
	  
	  def digest_key hash_key
	  	dig_key = hash_key.to_s + '_digest'
	  	dig_key = dig_key.to_sym if hash_key.is_a? Symbol
	  	dig_key
	  end

	  # Calculate all keys that should be kept in whitelist mode
	  # In multiple iterations of redact -> decrypt - digest keys will remain
	  # and then get deleted in the second iteration, so we have to
	  # add the digest keys so they're not wiped out on later iteration
  	  def whitelist_redact_hash redact_hash
  	    digest_hash = {}
  	    
  	  	redact_hash.each do |key,how|
  	  	  if (how == :digest)
  	  	    digest_hash[digest_key(key)] = :keep
  	  	  end
  	  	end
  	  	
  	  	digest_hash.merge redact_hash
	  end
  end

  class EncryptorInterface
    extend AttrEncrypted
    
    attr_encrypted :data
  end
end
