[![Gem Version](https://badge.fury.io/rb/hash_redactor.svg)](https://badge.fury.io/rb/hash_redactor)
[![Build Status](https://travis-ci.org/chrisjensen/hash_redactor.svg?branch=master)](https://travis-ci.org/chrisjensen/hash_redactor)
[![Test Coverage](https://codeclimate.com/github/chrisjensen/hash_redactor/badges/coverage.svg)](https://codeclimate.com/github/chrisjensen/hash_redactor/coverage)
[![Code Climate](https://codeclimate.com/github/chrisjensen/hash_redactor/badges/gpa.svg)](https://codeclimate.com/github/chrisjensen/hash_redactor)
[![security](https://hakiri.io/github/chrisjensen/hash_redactor/master.svg)](https://hakiri.io/github/chrisjensen/hash_redactor/master)

# HashRedactor

Used to redact a hash by removing, digesting or encrypting keys.

Makes use of [`attr_encrypted`](https://github.com/attr-encrypted/attr_encrypted) to perform encryption.

Useful if you have large JSON objects or similar that are coming in through API calls or elsewhere and you want to scrub the private data before storing it to the database.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'hash_redactor'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install hash_redactor

## Usage

Initialize the HashRedactor with a set of fields that you want to redact in hashes that get passed to it. 

You can choose 3 ways to redact each field:

+ `:keep` - The field is untouched (for use in `:whitelist` mode)
+ `:remove` - The field is simply deleted
+ `:digest` - The field is passed through a one way hash function (SHA256)
+ `:encrypt` - The field is encrypted

If you plan on using digest or encrypt, then you will need to specify `:digest_salt` or `:encryption_key` respectively in the options.

```ruby
fields_to_redact = {
	:ssn => :remove,
	:email => :digest,
	:medical_history => :encrypt
} 

redactor = HashRedactor::HashRedactor.new({
	redact: fields_to_redact,
	encryption_key: 'a really secure key no one will ever guess it',
	digest_salt: 'a secret salt'
})
```

Once initialized, you can simply call `#redact` on hashes of data.
If a key you have specified to redact is missing, HashRedactor will silently ignore it's absence.
Any key's not specified in your redact hash will be left unchanged.


```ruby
raw_data = {
	ssn: 'a very personal number',
	email: 'personal@email.com',
	medical_history: 'Some very private information'
	plaintext: 'This will never be changed'
}

safe_data = redactor.redact(raw_data)

safe_data[:ssn] # nil
safe_data[:email_digest] # One way hash of the email
safe_data[:encrypted_medical_history] # Encrypted medical history
safe_data[:plaintext] # This will never be changed
```

To retrieve your encrypted data, pass it through decrypt.

```ruby
loaded_data = redactor.decrypt(safe_data)
loaded_data[:medical_history] # 'Some very private information'
```

## Digest method

Digest may be used in cases where you don't want to keep the data due to privacy concerns, but want to compare it.
For example, maybe you have a large database of people whom you never need to contact by email, but you want to use the email address to check for duplicates.

To enhance protection of the data you should provide a salt in the configuration options and you should not store that salt in your database.

Once the field has been digested, it's key will have _digest appended.

## Encrypt method

Encryption is for fields that you do need to recover, but don't want to store in plaintext in the database.

[`attr_encrypted`](https://github.com/attr-encrypted/attr_encrypted) is used to perform encryption.

Once the field has been encrypted, the original field is removed from the hash, and replaced with `:encrypted_FIELDNAME` and `:encrypted_FIELDNAME_iv` - both these fields must be present in the hash for decrypt to succeed.

For example, if the field you want to encrypt has the key `:email`, then the redacred hash will have the keys `:encrypted_email` and `:encrypted_email_iv`.

## Redacted Hash

From the example above, after running #redact, the safe_data hash would look something like this:

```ruby
{
	:email_digest=>"VXJsQeG81HYWOb30XfpBdbqEFH1f4VaFLTqHCdxCmj8=", :encrypted_medical_history=>"2JIN3Yhxvm/m7qlE+n4pMT9yckXuPa+2IlMBFQMcbP1pcwyrG7wy0TP4scgx\n",
	:encrypted_medical_history_iv=>"tqMQa1aYTdJuMhrD\n",
	:plaintext => 'This will never be changed'
}
```

## Options

Default options are:
```ruby
  	  	  digest_salt: 		 "",
		  encryption_key:	 nil,
		  encode:            true,
		  encode_iv:         true,
		  default_encoding:  'm',
		  filter_mode:		 :blacklist
```

### :digest_salt

Salt to use when applying digest method

### :encryption_key

Key to use for encryption and decryption of values

### :encode, :encode_iv, :default_encoding

Determines how (if at all) to encode the encrypted data and it's iv

The default encoding is m (base64). You can change this by setting encode: `'some encoding'`. See [Arrary#pack](http://ruby-doc.org/core-2.3.0/Array.html#method-i-pack) for more encoding options.

### filter_mode

Filter mode determines how keys that are not included in the redact option are handled.
It can be either `:whitelist` or `:blacklist`

In `:blacklist` mode the default, it will leave unspecified keys untouched.
In `:whitelist` mode any keys not specified will be removes.

```ruby
redactor = HashRedactor::HashRedactor.new({
	redact: { :id => :keep, :ssn => :remove, :history => :encrypt, :email => :digest" },
	encryption_key: 'a really secure key no one will ever guess it',
	digest_salt: 'a secret salt'
})

data = {
  id: 42,
  ssn: 'my ssn number',
  history: 'Intriguing"
  email: 'personal@email.com',
  age: "that's personal"
}

result = reactor.redact data
result[:id]					# 42
result[:ssn]				# nil
result[:encrypted_history]  # encrypted value
result[:email_digest]		# digest of email

result[:age]				# "that's personal"

result = reactor.redact data, :filter_mode => :whitelist

result[:id]					# 42 (because of :id => :keep)
result[:ssn]				# nil
result[:encrypted_history]  # encrypted value
result[:email_digest]		# digest of email

result[:age]				# nil (because it wasn't explicitly whitelisted)

```

*Note:* To prevent accidental deletion of digest information during repeated loading and unloading data, the digest of all values is implicitly assumed to be :keep.
eg If your redact hash includes `:email => :digest`, it is assumed to also contain `:email_digest => :keep`

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release` to create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

1. Fork it ( https://github.com/chrisjensen/hash_redactor/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
