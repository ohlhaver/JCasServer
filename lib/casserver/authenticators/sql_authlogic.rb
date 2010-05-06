require 'casserver/authenticators/sql'

# These were pulled directly from Authlogic, and new ones can be added
# just by including new Crypto Providers
require File.dirname(__FILE__) + '/authlogic_crypto_providers/aes256'
require File.dirname(__FILE__) + '/authlogic_crypto_providers/bcrypt'
require File.dirname(__FILE__) + '/authlogic_crypto_providers/md5'
require File.dirname(__FILE__) + '/authlogic_crypto_providers/sha1'
require File.dirname(__FILE__) + '/authlogic_crypto_providers/sha256'
require File.dirname(__FILE__) + '/authlogic_crypto_providers/sha512'

begin
  require 'active_record'
rescue LoadError
  require 'rubygems'
  require 'active_record'
end

# This is a version of the SQL authenticator that works nicely with Authlogic. 
# Passwords are encrypted the same way as it done in Authlogic. 
# Before use you this, you MUST configure rest_auth_digest_streches and rest_auth_site_key in 
# config. 
#
# Using this authenticator requires restful authentication plugin on rails (client) side.
#
# * git://github.com/binarylogic/authlogic.git
# 
# Usage:

# authenticator:
#   class: CASServer::Authenticators::SQLAuthlogic
#   database:
#     adapter: mysql
#     database: some_database_with_users_table
#     user: root
#     password:
#     server: localhost
#   user_table: user
#   username_column: login
#   password_column: crypted_password
#   salt_column: password_salt
#   encryptor: BCrypt
#
class CASServer::Authenticators::SQLAuthlogic < CASServer::Authenticators::SQL

  def validate(credentials)
    read_standard_credentials(credentials)
    
    raise CASServer::AuthenticatorError, "Cannot validate credentials because the authenticator hasn't yet been configured" unless @options
    
    user_model, preference_model = establish_database_connection_if_necessary
    
    username_column = @options[:user_attributes][:username]
    password_column = @options[:user_attributes][:password]
    salt_column     = @options[:user_attributes][:salt]
    old_salt_column = @options[:user_attributes][:old_salt]
    encrypt_function = @options[:encrypt_function] || 'user.encrypted_password == Digest::SHA256.hexdigest("#{user.encryption_salt}::#{@password}")'
    
    @username = @username.to_s.downcase.gsub(' ', '_')
    results = user_model.find(:all, :select => @options[:user_attributes].values.join(',') , :conditions => ["#{username_column} = ?", @username ])

    begin
      encryptor = eval("Authlogic::CryptoProviders::" + @options[:encryptor] || "Sha512")
    rescue StandardError => message
      encryptor = Authlogic::CryptoProviders::Sha512
    end

    if results.size > 0
      $LOG.warn("Multiple matches found for user '#{@username}'") if results.size > 1
      user = results.first
      @extra_attributes = { 'auth' => 'jurnalo' }
      user_id_column = @options[:preference_attributes][:user_id]
      user_type_column = @options[:preference_attributes][:user_type]
      conditions = { user_id_column => user.id }
      conditions.merge!( user_type_column => (@options[:users_table] || 'users').classify ) unless user_type_column.blank?
      preference = preference_model.find( :first, :select => @options[:preference_attributes].values.join(','), :conditions => conditions )
      @options[:preference_attributes].each do | key, value |
        next if [ user_id_column, user_type_column ].include?( value )
        @extra_attributes[ key.to_s ] = preference.send( value )
      end
      @options[:user_attributes].each do | key, value |
        next if [ username_column, password_column, salt_column, old_salt_column ].include?( value )
        @extra_attributes[ key.to_s ] = user.send( value )
      end
      $LOG.debug("#{self.class}: Read the following extra_attributes for user #{@username.inspect}: #{@extra_attributes.inspect}")
      if !salt_column.nil? && user.send(salt_column).blank?
        return eval(encrypt_function)
      else
        tokens = [@password, (not salt_column.nil?) && user.send(salt_column) || nil].compact
        crypted = user.send(password_column)
        return encryptor.matches?(crypted, tokens)
      end
    else
      return false
    end
  end
end
