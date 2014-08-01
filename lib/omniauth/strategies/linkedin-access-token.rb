require 'oauth2'
require 'omniauth'

module OmniAuth
  module Strategies
    class LinkedinAccessToken
      include OmniAuth::Strategy

      option :name, 'linkedin_access_token'

      args [:client_id, :client_secret]

      option :client_id, nil
      option :client_secret, nil

      option :client_options, {
        :site => 'https://api.linkedin.com',
        :token_url => '/oauth/access_token',
        :ssl => { :version => "SSLv3" }
      }

      option :access_token_options, {
        :mode => :query,
        :param_name => 'oauth2_access_token'
      }

      option :fields, ["id", "email-address", "first-name", "last-name", 
                       "headline", "industry", "picture-url", "location",
                       "public-profile-url"]

      option :scope, 'r_basicprofile r_emailaddress'

      attr_accessor :access_token
      alias :oauth2_access_token :access_token

      uid { raw_info['id'] }

      info do
        name = [raw_info['firstName'], raw_info['lastName']].compact.join(' ').strip || nil
        name = nil_if_empty(name)
        prune!({
          :name => name,
          :email => raw_info['emailAddress'],
          :nickname => name,
          :first_name => raw_info['firstName'],
          :last_name => raw_info['lastName'],
          :location => parse_location(raw_info['location']),
          :description => raw_info['headline'],
          :image => raw_info['pictureUrl'],
          :headline => raw_info['headline'],
          :industry => raw_info['industry'],
          :urls => {
            :public_profile => raw_info['publicProfileUrl']
          },
        })
      end

      extra do
        hash = {}
        hash['raw_info'] = raw_info unless skip_info?
        prune! hash
      end

      credentials do
        hash = {'token' => access_token.token}
        hash.merge!('refresh_token' => access_token.refresh_token) if access_token.expires? && access_token.refresh_token
        hash.merge!('expires_at' => access_token.expires_at) if access_token.expires?
        hash.merge!('expires' => access_token.expires?)
        hash
      end

      def raw_info
        fields = options.fields
        fields.map! {|f| f == 'picture-url' ? 'picture-url;secure=true' : f } if options[:secure_image_url]
        @raw_info ||= access_token.get("v1/people/~:(#{fields.join(',')})?format=json").parsed
      end

      def info_options
        options[:info_fields] ? {:params => {:fields => options[:info_fields]}} : {}
      end

      def client
        ::OAuth2::Client.new(options.client_id, options.client_secret, deep_symbolize(options.client_options))
      end

      def request_phase
        options.request_params ||= {}
        options.request_params[:scope] = options.scope.gsub("+", " ")
        super
      end

      def callback_phase
        if !request.params['access_token'] || request.params['access_token'].to_s.empty?
          raise ArgumentError.new("No access token provided.")
        end

        self.access_token = build_access_token
        self.access_token = self.access_token.refresh! if self.access_token.expired?

        # Instead of calling super, duplicate the functionlity, but change the provider to 'linkedin'.
        # This is done in order to preserve compatibilty with the regular linked provider
        hash = auth_hash
        hash[:provider] = "linkedin"
        self.env['omniauth.auth'] = hash
        call_app!

       rescue ::OAuth2::Error => e
         fail!(:invalid_credentials, e)
       rescue ::MultiJson::DecodeError => e
         fail!(:invalid_response, e)
       rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
         fail!(:timeout, e)
       rescue ::SocketError => e
         fail!(:failed_to_connect, e)
      end

      protected

      def parse_location(location_hash = {})
        location_hash ||= {}
        location_name = extract_location_name(location_hash)
        country_code = extract_country_code(location_hash)
        build_location_value(location_name, country_code)
      end

      def extract_location_name(location_hash = {})
        nil_if_empty(location_hash["name"])
      end

      def extract_country_code(location_hash = {})
        country_hash = location_hash["country"] || {}
        country_code = nil_if_empty(country_hash["code"])
        country_code = (country_code ? country_code.upcase : nil)
      end

      def build_location_value(location_name, country_code)
        nil_if_empty([location_name, country_code].compact.join(', '))
      end

      def nil_if_empty(value)
        (value.nil? || value.empty?) ? nil : value
      end

      def deep_symbolize(hash)
        hash.inject({}) do |h, (k,v)|
          h[k.to_sym] = v.is_a?(Hash) ? deep_symbolize(v) : v
          h
        end
      end

      def build_access_token
        # Options supported by `::OAuth2::AccessToken#initialize` and not overridden by `access_token_options`
        hash = request.params.slice("access_token", "expires_at", "expires_in", "refresh_token")
        hash.update(options.access_token_options)
        ::OAuth2::AccessToken.new(
          client,
          hash["access_token"],
          {
            :mode => :query,
            :param_name => 'oauth2_access_token',
            :expires_in => hash["expires_in"],
            :expires_at => hash["expires_at"],
            :refresh_token => hash["refresh_token"]
          }
        )
      end

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end
    end
  end
end
