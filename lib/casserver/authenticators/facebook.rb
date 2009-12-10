require 'casserver/authenticators/base'
require 'timeout'
require 'mechanize'

# Validates Facebook accounts against Facebook's authentication service -- in other 
# words, this authenticator allows users to log in to CAS using their
# Facebook accounts.

class CASServer::Authenticators::Facebook < CASServer::Authenticators::Base

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
        if ( post_login_page.uri.to_s ==  "http://www.facebook.com/home.php?" ) then
          @extra_attributes = { 'auth' => 'facebook' }
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
  
end
