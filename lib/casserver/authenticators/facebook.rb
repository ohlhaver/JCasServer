require 'casserver/authenticators/base'
#require 'timeout'
#require 'mechanize'

# Validates the Facebook Connect Authenticated Accounts to our CAS Server

class CASServer::Authenticators::Facebook < CASServer::Authenticators::SQL
  
  def facebook?
    true
  end

  def validate(credentials)
    read_standard_credentials(credentials)
    
    raise CASServer::AuthenticatorError, "Cannot validate credentials because the authenticator hasn't yet been configured" unless @options

    return false if @username.blank? || @password.blank?
    
    user_model, preference_model = establish_database_connection_if_necessary
    
    require 'pp'
    pp @options
    
    username_column = @options[:user_attributes][:fb_user_id] 
    password_column = @options[:user_attributes][:fb_access_token]
    
    results = user_model.find(:all, :select => @options[:user_attributes].values.join(','), :conditions => [ "#{username_column} = ?", @username ])
    
    if results.size > 0
      $LOG.warn("#{self.class}: Multiple matches found for user #{@username.inspect}") if results.size > 1
      user = results.first
      @extra_attributes = { 'auth' => 'facebook' }
      fb_access_token   = user.send( password_column )
      fb_user_id        = user.send( username_column )
      @password_salt    = @password[0,24]
      fb_hmac           = @password_salt + Digest::SHA1.hexdigest( "#{fb_user_id}#{@password_salt}#{fb_access_token}" )
      if fb_hmac == @password
        conditions = { @options[:preference_attributes][:user_id] => user.id }
        conditions.merge!( @options[:preference_attributes][:user_type] => (@options[:users_table] || 'users').classify ) unless @options[:preference_attributes][:user_type].blank?
        preference = preference_model.find( :first, :select => @options[:preference_attributes].values.join(','), :conditions => conditions )
        @options[:preference_attributes].each do | key, value |
          next if [ 'user_id', 'user_type' ].include?( key.to_s )
          @extra_attributes[ key.to_s ] = preference.send( value )
        end
        @options[:user_attributes].each do | key, value |
          next if %w(password salt old_salt username fb_user_id fb_access_token).include?( key.to_s )
          @extra_attributes[ key.to_s ] = user.send( value )
        end
        return true
      end
    end
    return false
  end
  
  # def populate_extra_attributes
  #   user_model, preference_model = establish_database_connection_if_necessary
  #   username_column = @options[:user_attributes][:username]
  #   user = user_model.find(:first, :select => @options[:user_attributes].values.join(',') , :conditions => ["#{username_column} = ?", @username])
  #   return unless user
  #   user_id_column = @options[:preference_attributes][:user_id]
  #   user_type_column = @options[:preference_attributes][:user_type]
  #   conditions = { user_id_column => user.id }
  #   conditions.merge!( user_type_column => (@options[:users_table] || 'users').classify ) unless user_type_column.blank?
  #   preference = preference_model.find(:first, :select => @options[:preference_attributes].values.join(','), :conditions => conditions)
  #   @options[:preference_attributes].each do | key, value |
  #     next if [ user_id_column, user_type_column ].include?( value )
  #     @extra_attributes[ key.to_s ] = preference.send( value )
  #   end
  #   @options[:user_attributes].each do | key, value |
  #     next if username_column == value
  #     @extra_attributes[ key.to_s ] = user.send( value )
  #   end
  #   $LOG.debug("#{self.class}: Read the following extra_attributes for user #{@username.inspect}: #{@extra_attributes.inspect}")
  # end
  
end
