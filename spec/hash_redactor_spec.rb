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
	
    it "removes data" do
		result = subj.redact(data, redact: subhash(redact, :ssn))
		expect(result).not_to have_key(:ssn)
    end
    
    it "digests data" do
		result = subj.redact(data, redact: subhash(redact, :email))
		expect(result[:email_digest]).not_to eq(nil)
		expect(result[:email_digest]).not_to eq(data[:email])
    end

    it "removes plaintext of digested data" do
		result = subj.redact(data, redact: subhash(redact, :email))
		expect(result).not_to have_key(:email)
	end
    
    it "encrypts data" do
		result = subj.redact(data, redact: subhash(redact, :address))
		expect(result).to have_key(:encrypted_address)

		expect(result[:encrypted_address]).not_to eq(nil)
		expect(result[:encrypted_address]).not_to eq(data[:address])
	end
	
    it "removes plaintext of encrypted data" do
		result = subj.redact(data, redact: subhash(redact, :address))
		expect(result).not_to have_key(:address)
	end
    
	it "raises error on bad operation" do
		expect do
			subj.redact(data, redact: { :email => :weird_new_operation })
		end.to raise_error("redact called with unknown operation on email: weird_new_operation")
	end

    it "digested data should be comparable" do
      data2 = { email: 'george@example.com' }
	  result = subj.redact(data, redact: subhash(redact, :email))
	  result2 = subj.redact(data2, redact: subhash(redact, :email))
	  
	  expect(result[:email_digest]).not_to eq(nil)
	  expect(result[:email_digest]).to eq(result2[:email_digest])
    end
    
    it "salt should change digest" do
      data2 = { email: 'george@example.com' }
	  result = subj.redact(data, redact: subhash(redact, :email),
	  							 digest_salt: 'saltsaltsalt')
	  result2 = subj.redact(data2, redact: subhash(redact, :email))

	  expect(result[:email_digest]).not_to eq(nil)
	  expect(result[:email_digest]).not_to eq(result2[:email_digest])
    end
    
    it "leaves other data unchanged" do
      data2 = { unspecified: 'leave me alone' }
	  result = subj.redact(data2, redact: subhash(redact, :email))
	  expect(result[:unspecified]).to eq('leave me alone')
    end
    
    it "iv should vary by instance" do
	  result = subj.redact(data, redact: subhash(redact, :address))
      data2 = { address: 'Somewhere over the rainbow' }
	  result2 = subj.redact(data2, redact: subhash(redact, :address))
	  expect(result[:encrypted_address_iv]).not_to eq(result2[:encrypted_address_iv])
    end

    it "encrypted text should vary by instance" do
	  result = subj.redact(data, redact: subhash(redact, :address))
      data2 = { address: 'Somewhere over the rainbow' }
	  result2 = subj.redact(data2, redact: subhash(redact, :address))
	  expect(result[:encrypted_address]).not_to eq(result2[:encrypted_address])
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

	encoding_contexts = { "with encoding" => {}, "encode iv only" => { encode: false },
		 "encode value only" => { encode_iv: false },
		 "no encoding" => { encode_iv: false, encode: false }}

	encoding_contexts.each do |c,context_opts|
		context c do
			it "encrypted data should be decrypted" do
				r = HashRedactor::HashRedactor.new(options.merge context_opts)

				crypted = r.redact(data, redact: subhash(redact, :address))
				
				decrypted = r.decrypt(crypted, redact: subhash(redact, :address))
		
				expect(decrypted[:address]).to eq(data[:address])
			end
		end
	end
  end
end
