require 'sinatra'
require 'omniauth'
require 'openid/store/filesystem'
require 'yaml'

use OmniAuth::Builder do
  provider :open_id, OpenID::Store::Filesystem.new('/tmp')
end

enable :sessions
enable :run

get '/' do
  redirect '/auth/open_id'
end

post '/auth/:name/callback' do
  "<pre>#{YAML.dump(request.env['omniauth.auth'])}</pre>"
end
