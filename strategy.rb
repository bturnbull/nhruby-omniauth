require 'sinatra'
require 'omniauth'
require 'digest/sha1'
require 'yaml'

##############################################################
# An OmniAuth strategy to interface with our custom provider #
##############################################################

module OmniAuth
  module Strategies
    class OnlyOddNames
      include OmniAuth::Strategy

      def initialize(app, secret, auth_url, opts = {})
        @secret   = secret
        @auth_url = auth_url
        super(app, :only_odd_names, opts)
      end

      def request_phase
        response = Rack::Response.new
        response.redirect("#{@auth_url}?redirect_uri=#{URI.escape(callback_url)}")
        response.finish
      end

      def callback_phase
        if request.params['error']
          fail!(:user_auth)
        else
          username  = request.params['username'].to_s
          auth_code = request.params['auth_code'].to_s
          if auth_code == Digest::SHA1.hexdigest(@secret + username)
            @auth_code = auth_code
            @username  = username
            super
          else
            fail!(:trust_failure)
          end
        end
      end

      def auth_hash
        OmniAuth::Utils.deep_merge(super(),
          { 'username'    => @username,
            'user_info'   => {'name' => @username},
            'credentials' => {'auth_code' => @auth_code} })
      end

    end
  end
end

################################
# Our humble demonstration app #
################################

# The shared secret that makes us feel secure ;-)
def secret ; 'Shama-Lama-Ding-Dong' ; end

configure do
  set :secret, Proc.new { secret } 
  set :port, 8080
end

enable :run

use OmniAuth::Builder do
  provider :only_odd_names, secret, '/provider/auth'
end

get '/' do
  redirect '/auth/only_odd_names'
end

get '/auth/:name/callback' do
  "<pre>#{YAML.dump(request.env['omniauth.auth'])}</pre>"
end

get '/auth/failure' do
  error = request.env['omniauth.error']
  case params['message'].to_sym
  when :user_auth
    'Not Odd Enough!'
  when :trust_failure
    "Something wicked this way comes.  We have trust issues."
  else
    'Sent us up the bomb!'
  end
end

#################################################
# Our authentication provider - could be remote #
#################################################

# If a name has an odd number of characters then authenticates.
#
# Form -> GET /provider/auth?redirect_uri=:redirect_uri
# API  -> POST /provider/auth?redirect_uri=:redirect_uri&username=:username
#
# Success -> GET :redirect_uri?auth_code=:auth_code&username=:username
# Failure -> GET :redirect_uri?error=:message
#
# :auth_code is the SHA1 digest of the shared secret + :username

get '/provider/auth' do
  <<-HTML
  <form action='/provider/auth' method='post'>
    <input type='hidden' name='redirect_uri' value='#{request.params['redirect_uri']}' />
    <label for='username'>Who are you?</label>
    <input id='username' type='text' name='username' />
    <input type='submit' value='Sign In' />
  </form>
  HTML
end

post '/provider/auth' do
  username = request.params['username'].to_s.strip
  auth_code = Digest::SHA1.hexdigest(secret + username)
  if username && username.length % 2 == 1
    redirect "#{request.params['redirect_uri']}?auth_code=#{auth_code}&username=#{username}"
  else
    redirect "#{request.params['redirect_uri']}?error=Not%20Odd%20Enough"
  end
end

