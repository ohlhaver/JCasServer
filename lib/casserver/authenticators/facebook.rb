require 'casserver/authenticators/base'
require 'timeout'
require 'mechanize'

# Validates Facebook accounts against Facebook's authentication service -- in other 
# words, this authenticator allows users to log in to CAS using their
# Facebook accounts.

class CASServer::Authenticators::Facebook < CASServer::Authenticators::SQL

  def validate(credentials)
    read_standard_credentials(credentials)

    return false if @username.blank? || @password.blank?
    return false unless EmailRegex.match( @username )
    
    a = WWW::Mechanize.new { |agent|
      agent.user_agent_alias = 'Mac Safari'
    }
    
    page = a.get('https://login.facebook.com/login.php')
    login_form = page.forms.first
    login_form.email = @username
    login_form.pass = @password
    wait_seconds = 30
    begin
      timeout( wait_seconds ) do
        post_login_page = login_form.submit
        if ( post_login_page.uri.to_s ==  "http://www.facebook.com/home.php?" ) || post_login_page.forms.first.has_field?('answered_captcha') then
          @extra_attributes = { 'auth' => 'facebook' }
          populate_extra_attributes
          true
        else
          false
        end
      end
    rescue Timeout::Error => message
      $LOG.error("Facebook did not respond to the credential validation request. We waited for #{wait_seconds.inspect} seconds before giving up.")
      raise CASServer::AuthenticatorError, "Timeout while waiting for Facebook to validate credentials."
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
    preference = preference_model.find(:first, :select => @options[:preference_attributes].values.join(','), :conditions => conditions)
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
