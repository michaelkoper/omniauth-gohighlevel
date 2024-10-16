# frozen_string_literal: true

require_relative 'gohighlevel/version'
require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Gohighlevel < OmniAuth::Strategies::OAuth2
      option :name, 'gohighlevel'

      option :client_options, {
        site: 'https://marketplace.gohighlevel.com',
        authorize_url: 'https://marketplace.gohighlevel.com/oauth/chooselocation',
        token_url: 'https://services.leadconnectorhq.com/oauth/token'
      }

      option :authorize_params, {
        response_type: 'code',
        user_type: 'Location'
      }

      def build_access_token
        verifier = request.params['code']
        @token = client.auth_code.get_token(
          verifier,
          {
            redirect_uri: callback_url,
            client_id: options.client_id,
            client_secret: options.client_secret,
            grant_type: 'authorization_code',
            user_type: 'Location'
          },
          { headers: { 'Accept' => 'application/json' } }
        )
        @token
      rescue ::OAuth2::Error => e
        Rails.logger.error "OAuth2 Error: #{e.code} - #{e.description}"
        Rails.logger.error "Response body: #{e.response.body}" if e.response
        raise e
      rescue StandardError => e
        Rails.logger.error "Error during token exchange: #{e.class.name} - #{e.message}"
        Rails.logger.error e.backtrace.join("\n")
        raise e
      end

      def callback_phase
        if request.params['error'] || request.params['error_reason']
          raise CallbackError.new(request.params['error'],
                                  request.params['error_description'] || request.params['error_reason'], request.params['error_uri'])
        elsif !request.params['code']
          fail!(:missing_code, OmniAuth::Error.new('Missing code parameter'))
        else
          options.token_params['redirect_uri'] = callback_url
          super
        end
      rescue CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::OAuth2::Error, CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      def authorize_params
        super.tap do |params|
          params[:scope] = request.params['scope'] if request.params['scope']
          params[:user_type] = 'Location'
        end
      end

      uid { @token.params[:user_id] }

      info do
        {
          user_id: raw_info['user_id'],
          location_id: raw_info['location_id']
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.params.slice('company_id', 'location_id', 'user_id', 'user_type')
      end

      def callback_url
        full_host + script_name + callback_path
      end
    end
  end
end
