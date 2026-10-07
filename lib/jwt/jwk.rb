# frozen_string_literal: true

require_relative 'jwk/key_finder'
require_relative 'jwk/set'

module JWT
  # JSON Web Key (JWK)
  module JWK
    class << self
      def create_from(key, params = nil, options = {})
        if key.is_a?(Hash)
          jwk_kty = key[:kty] || key['kty']
          raise JWT::JWKError, 'Key type (kty) not provided' unless jwk_kty

          jwk = mappings.fetch(jwk_kty.to_s) do |kty|
            raise JWT::UnsupportedKeyType, "Key type #{kty} not supported"
          end.new(key, params, options)

          validate_certificate_binding!(jwk, options)

          return jwk
        end

        mappings.fetch(key.class) do |klass|
          raise JWT::JWKError, "Cannot create JWK from a #{klass.name}"
        end.new(key, params, options)
      end

      def classes
        @mappings = nil # reset the cached mappings
        @classes ||= []
      end

      alias new create_from
      alias import create_from

      private

      def mappings
        @mappings ||= generate_mappings
      end

      def generate_mappings
        classes.each_with_object({}) do |klass, hash|
          next unless klass.const_defined?('KTYS')

          Array(klass::KTYS).each do |kty|
            hash[kty] = klass
          end
        end
      end

      # Validates the x5c certificate chain of a JWK against caller-provided
      # trust anchors when the :x5c option is given. JWKs without an x5c
      # member are imported as before. A JWK that fails validation raises
      # and is therefore never returned or cached for verification.
      def validate_certificate_binding!(jwk, options)
        binding_options = options && options[:x5c]
        return unless binding_options && jwk[:x5c]

        CertificateBinding.new(
          root_certificates: binding_options[:root_certificates],
          crls: binding_options[:crls],
          time: binding_options[:time],
          algorithms: binding_options[:algorithms]
        ).validate(jwk)
      end
    end
  end
end

require_relative 'jwk/key_base'
require_relative 'jwk/ec'
require_relative 'jwk/rsa'
require_relative 'jwk/hmac'
require_relative 'jwk/certificate_binding'
