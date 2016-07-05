require 'attr_encrypted'

module HashRedactor
  class HashRedactor
	  def initialize(opts = {})
		@options = default_options.merge opts

		@options[:encode] = @options[:default_encoding] if @options[:encode] == true
		@options[:encode_iv] = @options[:default_encoding] if @options[:encode_iv] == true
	  end
  
  	  def default_options
  	  	{
  	  	  digest_salt: 		 "",
		  encode:            true,
		  encode_iv:         true,
		  default_encoding:  'm'
  	  	}
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
  
		redact_hash.each do |hash_key,how|
		  if data.has_key? hash_key
			case how
			  when :remove
				nil
			  when :digest
				result_key = (hash_key.to_s + '_digest').to_sym

				result[result_key] = Digest::SHA256.base64digest(
											result[hash_key] + options[:digest_salt])
			  when :encrypt
				raise "No encryption key specified. Please pass :encryption_key in options to new or redact" unless options[:encryption_key]
			  
				crypt_key = options[:encryption_key]
				iv = SecureRandom.random_bytes(12)
				data_key = ('encrypted_' + hash_key.to_s).to_sym
				iv_key = ('encrypted_' + hash_key.to_s + '_iv').to_sym
			
				encrypted_value = EncryptorInterface.encrypt(:data, result[hash_key], iv: iv, key: crypt_key)
				
				encrypted_value = [encrypted_value].pack(options[:encode]) if options[:encode]
				iv = [iv].pack(options[:encode_iv]) if options[:encode_iv]
			
				result[data_key] = encrypted_value
				result[iv_key] = iv
			  else
				raise "redact called with unknown operation on #{hash_key.to_s}: #{how.to_s}"
			end

			result.delete hash_key
		  end
		end
  
		result
	  end

	  def decrypt(data, opts = {})
	    options = @options.merge opts

  		redact_hash = options[:redact]

  		raise "Don't know what to decrypt. Please configure the redact hash when initializing or pass as an argument to #decrypt." unless redact_hash && redact_hash.any?

		raise "No encryption key specified. Please pass :encryption_key in options to new or decrypt" unless options[:encryption_key]
  
		result = data.clone
  
		redact_hash.each do |hash_key,how|
		  if (how == :encrypt)
			data_key = ('encrypted_' + hash_key.to_s).to_sym
			iv_key = ('encrypted_' + hash_key.to_s + '_iv').to_sym

			if (data.has_key? data_key)
			  iv = result[iv_key]
			  crypt_key = options[:encryption_key]

			  encrypted_value = result[data_key]

			  # Decode if necessary
			  iv = iv.unpack(options[:encode_iv]).first if options[:encode_iv]
			  encrypted_value = encrypted_value.unpack(options[:encode]).first if options[:encode]

			  decrypted_value = EncryptorInterface.decrypt(:data, encrypted_value,
				   iv: iv, key: crypt_key)
		
			  result[hash_key] = decrypted_value
			end
		  end
		end
  
		result
	  end
  end

  class EncryptorInterface
    extend AttrEncrypted
    
    attr_encrypted :data
  end
end
