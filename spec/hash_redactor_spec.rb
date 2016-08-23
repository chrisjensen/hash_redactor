require 'spec_helper'

describe HashRedactor do
  it 'has a version number' do
    expect(HashRedactor::VERSION).not_to be nil
  end

  let (:subj) { HashRedactor::HashRedactor.new(options) }
  
  let (:options) do
    {
		redact: redact,
		encryption_key: 'my really, really, really, secret key'
	}
  end
  
  let (:data) do
	{
		id: 5,
		email: 'george@example.com',
		ssn: "George's social security number",
		address: "#02-03 Big Building, 22nd St, NY"
	}
  end
  
  let (:redact) do
	{
		:email => :digest,
		:ssn => :remove,
		:address => :encrypt
	}
  end

  let (:string_data) do
	Hash[data.map{ |k, v| [k.to_s, v] }]
  end

  let (:string_redact) do
	Hash[redact.map{ |k, v| [k.to_s, v] }]
  end
  
  let (:redacts) do
  	{
  		"string keys" => string_redact,
  		"symbol keys" => redact,
  		"string mode" => redact.clone.tap { |r| r.each { |k,v| r[k] = v.to_s } }
  	}
  end

  let (:datas) do
  	{
  		"string keys" => string_data,
  		"symbol keys" => data,
  		"string mode" => data
  	}
  end

  def subhash(hash, *extract)
    hash.select{|key, value| extract.include?(key) }
  end

  describe "#redact" do
		context "incomplete configuration" do
			it "raises error for no redact hash" do
				r = HashRedactor::HashRedactor.new()
				expect do
					r.redact(data)
				end.to raise_error("Don't know what to redact. Please configure the redact hash when initializing or pass as an argument to redact.")
			end
	
			it "raises error if no encryption key given" do
				r = HashRedactor::HashRedactor.new(redact: redact)
				expect do
					r.redact(data)
				end.to raise_error("No encryption key specified. Please pass :encryption_key in options to new or redact")
			end
		end
	
		it "raises error on bad operation" do
			expect do
				subj.redact(data, redact: { :email => :weird_new_operation })
			end.to raise_error("redact called with unknown operation on email: weird_new_operation")
		end

	  { "empty string" => '', 'nil' => nil }.each do |description, value|
		context "with #{description} values" do
			it "can encrypt" do
				result = subj.redact({ address: value },
							 redact: subhash(redact, :address))
							 
				expect(result[:encrypted_address]).to eq(value)
			end
			
			it "can digest" do
				result = subj.redact({ email: value },
							 redact: subhash(redact, :email))

				expect(result[:email_digest]).to be_truthy
			end

			context "with options[:digest_empty] = false" do
				let (:options) do
				  {
					redact: subhash(redact, :email),
					digest_empty: false,
					encryption_key: 'my really, really, really, secret key'
				  }
				end

				it "digest remains empty" do
					result = subj.redact({ email: value },
								 options)

					expect(result[:email_digest]).to eq(value)
				end
			end
		end
	  end

	  { "string keys" => :to_s, 
	    "symbol keys" => :to_sym,
	    "string mode" => :to_sym }.each do |key_type,convert|
		context "#{key_type}" do
		  [ :blacklist, :whitelist ].each do |mode|
			context "mode: #{mode}" do			
				let (:options) do
				  {
					redact: redact,
					filter_mode: mode,
					encryption_key: 'my really, really, really, secret key'
				  }
				end
				
				it "removes data" do
					key = "ssn".send(convert)
			
					result = subj.redact(datas[key_type],
								 redact: subhash(redacts[key_type], key))
					expect(result).not_to have_key(key)
				end
	
				it "digests data" do
					key = "email".send(convert)
					digest_key = "email_digest".send(convert)

					result = subj.redact(datas[key_type],
										 redact: subhash(redacts[key_type], key))
					expect(result[digest_key]).not_to eq(nil)
					expect(result[digest_key]).not_to eq(data[key])
				end

				it "removes plaintext of digested data" do
					key = "email".send(convert)

					result = subj.redact(datas[key_type],
								 redact: subhash(redacts[key_type], key))
					expect(result).not_to have_key(key)
				end
	
				it "can digest numbers" do
					key = "email".send(convert)
					digest_key = "email_digest".send(convert)
			
					data = { key => 25 }
				
					result = subj.redact(data, redact: redacts[key_type])
				
					expect(result).to have_key(digest_key)
					expect(result[digest_key]).not_to be_nil
				end

				it "can encrypt numbers" do
					key = "address".send(convert)
					crypted_key = "encrypted_address".send(convert)

					data = { key => 25 }
				
					result = subj.redact(data, redact: redacts[key_type])
					expect(result).to have_key(crypted_key)
					expect(result[crypted_key]).not_to be_nil
				end
	
				it "encrypts data" do
					key = "address".send(convert)
					crypted_key = "encrypted_address".send(convert)

					result = subj.redact(datas[key_type],
							 redact: subhash(redacts[key_type], key))
					expect(result).to have_key(crypted_key)

					expect(result[crypted_key]).not_to eq(nil)
					expect(result[crypted_key]).not_to eq(data[key])
				end
	
				it "removes plaintext of encrypted data" do
					key = "address".send(convert)

					result = subj.redact(datas[key_type],
							 redact: subhash(redacts[key_type], key))
					expect(result).not_to have_key(key)
				end
	
				it "digested data should be comparable" do
				  key = "email".send(convert)
				  digest_key = "email_digest".send(convert)

				  data2 = { key => 'george@example.com' }

				  result = subj.redact(datas[key_type],
					 redact: subhash(redacts[key_type], key))
				  result2 = subj.redact(data2,
					 redact: subhash(redacts[key_type], key))
	  
				  expect(result[digest_key]).not_to eq(nil)
				  expect(result[digest_key]).to eq(result2[digest_key])
				end

				it "redact + decrypt should be repeatable" do
				  subj.options[:redact] = redacts[key_type]
				
				  first_redact = subj.redact(datas[key_type])
				  first_decrypt = subj.decrypt(first_redact)
				  second_redact = subj.redact(first_decrypt)
				  second_decrypt = subj.decrypt(second_redact)

				  expect(second_decrypt).not_to be_empty
				  expect(second_decrypt).to eq(first_decrypt)
				end

				it "redact + decrypt should be repeatable after encrypted value change" do
				  subj.options[:redact] = redacts[key_type]

				  key = "address".send(convert)

				  first_redact = subj.redact(datas[key_type])
				  first_decrypt = subj.decrypt(first_redact)
				  first_decrypt[key] = 'A new world'
				  second_redact = subj.redact(first_decrypt)
				  second_decrypt = subj.decrypt(second_redact)
				  third_redact = subj.redact(second_decrypt)
				  third_decrypt = subj.decrypt(third_redact)

				  expect(third_decrypt).not_to be_empty
				  expect(second_decrypt).to eq(third_decrypt)
				end
			  end
			end

			it "leaves other data unchanged by default" do
			  key = "unspecified".send(convert)

			  data2 = { key => 'leave me alone' }
			  
			  result = subj.redact(data2, redacts[key_type])
			  expect(result[key]).to eq('leave me alone')
			end
		end
	end

    context "whitelist mode" do
      let(:data_white) do
        data.merge(unspecified: "this should go", whitelisted: "this should stay")
      end
      
      let(:redact_white) do
        redact.merge(:whitelisted => :keep)
      end
    
      it "removes unspecified keys" do
		result = subj.redact(data_white, redact: redact_white, filter_mode: :whitelist)
		
		expect(result).not_to have_key(:unspecified)
      end
      
      it "keeps keys explicitly marked keep" do
		result = subj.redact(data_white, redact: redact_white, filter_mode: :whitelist)
		
		expect(result[:whitelisted]).not_to eq(nil)
		expect(result[:whitelisted]).not_to eq(data_white[:whitelist])
      end
    end

	context "indifferent to key type" do
		it "salt should change digest" do
		  data2 = { email: 'george@example.com' }
		  result = subj.redact(data, redact: subhash(redact, :email),
									 digest_salt: 'saltsaltsalt')
		  result2 = subj.redact(data2, redact: subhash(redact, :email))

		  expect(result[:email_digest]).not_to eq(nil)
		  expect(result[:email_digest]).not_to eq(result2[:email_digest])
		end
	
		it "iv should vary by instance" do
		  result = subj.redact(data, redact: subhash(redact, :address))
		  data2 = { address: 'Somewhere over the rainbow' }
		  result2 = subj.redact(data2, redact: subhash(redact, :address))
		  expect(result[:encrypted_address_iv]).not_to eq(result2[:encrypted_address_iv])
		end

		it "iv should be replaced on every redaction" do
		  result = subj.redact(data, redact: subhash(redact, :address))
		  first_iv = result[:encrypted_address_iv]
		  decrypted = subj.decrypt(result, redact: subhash(redact, :address))
		  decrypted[:address] = 'A new world'
	  
		  result = subj.redact(decrypted, redact: subhash(redact, :address))
		  expect(result[:encrypted_address_iv]).not_to eq(first_iv)
		end

		it "encrypted text should vary by instance" do
		  result = subj.redact(data, redact: subhash(redact, :address))
		  data2 = { address: 'Somewhere over the rainbow' }
		  result2 = subj.redact(data2, redact: subhash(redact, :address))
		  expect(result[:encrypted_address]).not_to eq(result2[:encrypted_address])
		end
	  end
	end
  
	  describe "#decrypt" do
		context "incomplete configuration" do
			it "raises error for no redact hash" do
				r = HashRedactor::HashRedactor.new()
				expect do
					r.decrypt(data)
				end.to raise_error("Don't know what to decrypt. Please configure the redact hash when initializing or pass as an argument to #decrypt.")
			end
	
			it "raises error if no encryption key given" do
				r = HashRedactor::HashRedactor.new(redact: redact)
				expect do
					r.decrypt(data)
				end.to raise_error("No encryption key specified. Please pass :encryption_key in options to new or decrypt")
			end
		end

	  { "empty string" => '', 'nil' => nil }.each do |description, value|
		context "with #{description} values" do
			it "can decrypt" do
				result = subj.redact({ address: value },
							 redact: subhash(redact, :address))
				decrypted = subj.decrypt(result, redact: subhash(redact, :address))
				
				expect(decrypted[:address]).to eq(value)
			end
		end
	  end

		encoding_contexts = { "with encoding" => {}, "encode iv only" => { encode: false },
			 "encode value only" => { encode_iv: false },
			 "no encoding" => { encode_iv: false, encode: false }}

	  { "string keys" => :to_s, "symbol keys" => :to_sym }.each do |key_type, convert|
	    context key_type do
			encoding_contexts.each do |c,context_opts|
				context c do
					it "encrypted data should be decrypted" do
						r = HashRedactor::HashRedactor.new(options.merge context_opts)
						key = "address".send(convert)

						crypted = r.redact(datas[key_type],
									 redact: subhash(redacts[key_type], key))
			
						decrypted = r.decrypt(crypted,
									 redact: subhash(redacts[key_type], key))
	
						expect(decrypted[key]).to eq(datas[key_type][key])
					end
				end
			end

			it "deletes iv" do
				key = "address".send(convert)
				iv_key = "encrypted_address_iv".send(convert)
			
				redacted = subj.redact(datas[key_type], 
								redact: subhash(redacts[key_type], key))
				decrypted = subj.decrypt(redacted, redact: redacts[key_type])
				expect(decrypted).not_to have_key(iv_key)
			end

			it "deletes encrypted value" do
				key = "address".send(convert)
				crypted_key = "crypted_address".send(convert)

				redacted = subj.redact(datas[key_type],
								 redact: subhash(redacts[key_type], key))
				decrypted = subj.decrypt(redacted, redact: redacts[key_type])
				expect(decrypted).not_to have_key(crypted_key)
			end
		  end
	  end
	  
	  it "decrypts with string modes" do
		data = { address: 5 }
		redact.each { |k,v| redact[k] = v.to_s }
		redacted = subj.redact(data, redact)
		expect(subj.decrypt(redacted)).to eq({ address: "5" })
	  end
	  
	  it "decrypts numbers" do
		data = { address: 5 }
		redacted = subj.redact(data)
		expect(subj.decrypt(redacted)).to eq({ address: "5" })
	  end
	end
end
