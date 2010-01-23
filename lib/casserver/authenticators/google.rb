require 'casserver/authenticators/base'
require 'uri'
require 'net/http'
require 'net/https'
require 'timeout'

# Validates Google accounts against Google's authentication service -- in other 
# words, this authenticator allows users to log in to CAS using their
# Gmail/Google accounts.
class CASServer::Authenticators::Google < CASServer::Authenticators::SQL
  def validate(credentials)
    read_standard_credentials(credentials)

    return false if @username.blank? || @password.blank?
    return false unless EmailRegex.match( @username )
    
    auth_data = {
      'Email'   => @username, 
      'Passwd'  => @password, 
      'service' => 'xapi', 
      'source'  => 'RubyCAS-Server',
      'accountType' => 'HOSTED_OR_GOOGLE'
    }
   
    url = URI.parse('https://www.google.com/accounts/ClientLogin')
    http = Net::HTTP.new(url.host, url.port)
    http.use_ssl = true
    
    # TODO: make the timeout configurable
    wait_seconds = 10
    begin
      timeout(wait_seconds) do
        res = http.start do |conn|
          req = Net::HTTP::Post.new(url.path)
          req.set_form_data(auth_data,'&')
          conn.request(req)
        end
        
        case res
        when Net::HTTPSuccess
          @extra_attributes = { 'auth' => 'google' }
          populate_extra_attributes
          true
        when Net::HTTPForbidden
          false
        else
          $LOG.error("Unexpected response from Google while validating credentials: #{res.inspect} ==> #{res.body}.")
          raise CASServer::AuthenticatorError, "Unexpected response received from Google while validating credentials."
        end
      end
    rescue Timeout::Error
      $LOG.error("Google did not respond to the credential validation request. We waited for #{wait_seconds.inspect} seconds before giving up.")
      raise CASServer::AuthenticatorError, "Timeout while waiting for Google to validate credentials."
    end

  end
  
  def populate_extra_attributes
    user_model, preference_model = establish_database_connection_if_necessary
    username_column = @options[:user_attributes][:username]
    user = user_model.find(:first, :select => @options[:user_attributes].values.join(',') , :conditions => ["#{username_column} = ?", @username])
    return unless user
    user_id_column = @options[:preference_attributes][:user_id]
    user_type_column = @options[:preference_attributes][:user_type]
    conditions = { user_id_column => user.id }
    conditions.merge!( user_type_column => (@options[:users_table] || 'users').classify ) unless user_type_column.blank?
    preference = preference_model.find(:first, :select => @options[:preference_attributes].values.join(','), :conditions => conditions )
    @options[:preference_attributes].each do | key, value |
      next if [ user_id_column, user_type_column ].include?( value )
      @extra_attributes[ key.to_s ] = preference.send( value )
    end
    @options[:user_attributes].each do | key, value |
      next if username_column == value
      @extra_attributes[ key.to_s ] = user.send( value )
    end
    $LOG.debug("#{self.class}: Read the following extra_attributes for user #{@username.inspect}: #{@extra_attributes.inspect}")
  end
end
