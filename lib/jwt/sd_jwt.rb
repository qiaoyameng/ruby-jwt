# frozen_string_literal: true

require 'digest'
require 'jwt/sd_jwt/disclosure'
require 'jwt/sd_jwt/digest_algorithm'
require 'jwt/sd_jwt/disclosed_tree'
require 'jwt/sd_jwt/hidden_value'
require 'jwt/sd_jwt/result'
require 'jwt/sd_jwt/verifier'

module JWT
  # Selective Disclosure JWT (SD-JWT) verification.
  #
  # Only the SHA-256 digest algorithm is supported and key binding JWTs
  # are not accepted.
  module SDJWT
    DIGEST_ALGORITHMS = { 'sha-256' => ::Digest::SHA256 }.freeze
    DEFAULT_DIGEST_ALGORITHM = 'sha-256'
    SD_KEY = '_sd'
    SD_ALG_KEY = '_sd_alg'
    ARRAY_PLACEHOLDER_KEY = '...'
    RESERVED_CLAIM_NAMES = [SD_KEY, SD_ALG_KEY, ARRAY_PLACEHOLDER_KEY].freeze

    module_function

    # Verifies the issuer signature of an SD-JWT and applies the given
    # disclosures to reconstruct the selectively disclosable claims.
    #
    # @param jwt [String] the issuer signed JWT.
    # @param disclosures [Array<String>] base64url encoded disclosures.
    # @param key [String] the key used to verify the issuer signature.
    # @param options [Hash] options passed to {JWT.decode} (e.g. algorithms).
    # @return [JWT::SDJWT::Result] the verification result.
    def verify(jwt, disclosures = [], key = nil, **options, &keyfinder)
      payload, header = JWT.decode(jwt, key, true, options, &keyfinder)
      Verifier.new(payload, disclosures, header: header).verify
    end

    # Verifies an SD-JWT presentation of the form
    # +jwt~disclosure~disclosure~...~+. Inputs carrying a key binding JWT
    # are rejected with {JWT::KeyBindingNotSupportedError}.
    #
    # @param presentation [String] the tilde separated SD-JWT presentation.
    # @param key [String] the key used to verify the issuer signature.
    # @param options [Hash] options passed to {JWT.decode} (e.g. algorithms).
    # @return [JWT::SDJWT::Result] the verification result.
    def verify_presentation(presentation, key = nil, **options, &keyfinder)
      jwt, disclosures = split_presentation(presentation)
      verify(jwt, disclosures, key, **options, &keyfinder)
    end

    def split_presentation(presentation)
      raise MalformedSDJWTError, 'SD-JWT presentation must be a non-empty string' unless presentation.is_a?(String) && !presentation.empty?

      segments = presentation.split('~', -1)
      jwt = segments.shift
      raise MalformedSDJWTError, 'SD-JWT presentation is missing the issuer signed JWT' if jwt.empty?

      last = segments.last
      raise KeyBindingNotSupportedError, 'Key binding JWTs are not supported' if last.to_s.include?('.')

      segments.pop if last.to_s.empty?
      [jwt, segments]
    end
    private_class_method :split_presentation
  end
end
