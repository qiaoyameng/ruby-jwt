# frozen_string_literal: true

require 'digest'

module JWT
  # An immutable snapshot of a successful token verification.
  #
  # A VerifyResult is bound to the exact signature bytes, the verification
  # policy (signature algorithm and claims) and the moment the verification
  # happened. All nested structures (hashes, arrays and strings) are deeply
  # duplicated and frozen, so neither the caller nor the {EncodedToken} the
  # result was created from can alter the verified data afterwards.
  #
  #   encoded_token = JWT::EncodedToken.new(token)
  #   result = encoded_token.verify_result(signature: { algorithm: 'HS256', key: 'secret' })
  #   result.payload        # => {'pay' => 'load'} (frozen)
  #   result.verified_at    # => 2024-01-01 12:00:00 UTC
  #   result.claim_verified?(:exp) # => true
  class VerifyResult
    # Returns the verified header of the token.
    # @return [Hash] a deeply frozen copy of the header.
    attr_reader :header

    # Returns the verified payload of the token.
    # @return [Hash] a deeply frozen copy of the payload.
    attr_reader :payload

    # Returns the raw signature bytes that were verified.
    # @return [String] a frozen copy of the signature.
    attr_reader :signature

    # Returns the hex encoded SHA256 digest of the verified signature bytes.
    # @return [String] the digest of the signature.
    attr_reader :signature_digest

    # Returns the signing input that was verified.
    # @return [String] a frozen copy of the signing input.
    attr_reader :signing_input

    # Returns the token as it was when the verification happened.
    # @return [String] a frozen copy of the token.
    attr_reader :jwt

    # Returns the claims that were actually verified.
    #
    # Claims that were only parsed, or whose verification was not requested,
    # are not included.
    #
    # @return [Array<Symbol>] a frozen list of the verified claims.
    attr_reader :verified_claims

    # Returns the signature algorithm(s) the signature was verified against.
    # @return [String, Array, Object] a frozen copy of the algorithm option.
    attr_reader :signature_algorithm

    # Returns the moment the verification was performed.
    # @return [Time] the verification time.
    attr_reader :verified_at

    # Initializes a new VerifyResult instance.
    #
    # @param header [Hash] the verified header.
    # @param payload [Hash] the verified payload.
    # @param signature [String] the raw signature bytes that were verified.
    # @param signing_input [String] the signing input that was verified.
    # @param jwt [String] the token at the moment of verification.
    # @param verified_claims [Array<Symbol>] the claims that were verified.
    # @param signature_algorithm [String, Array, Object] the algorithm option used for verification.
    # @param verified_at [Time] the moment the verification was performed.
    def initialize(header:, payload:, signature:, signing_input:, jwt:, verified_claims:, signature_algorithm:, verified_at:) # rubocop:disable Metrics/ParameterLists
      @header = VerifyResult.deep_freeze(header)
      @payload = VerifyResult.deep_freeze(payload)
      @signature = VerifyResult.deep_freeze(signature)
      @signature_digest = Digest::SHA256.hexdigest(@signature)
      @signing_input = VerifyResult.deep_freeze(signing_input)
      @jwt = VerifyResult.deep_freeze(jwt)
      @verified_claims = VerifyResult.deep_freeze(verified_claims.map(&:to_sym))
      @signature_algorithm = VerifyResult.deep_freeze(signature_algorithm)
      @verified_at = verified_at.freeze

      freeze
    end

    # Returns whether the given claim was actually verified.
    #
    # Claims that were only parsed, or whose verification was not requested,
    # are not reported as verified.
    #
    # @param claim [String, Symbol] the name of the claim.
    # @return [Boolean] true if the claim was verified, false otherwise.
    def claim_verified?(claim)
      verified_claims.include?(claim.to_sym)
    end

    # Returns whether the token was verified. Always true for a VerifyResult,
    # as instances are only created for successful verifications.
    #
    # @return [true]
    def verified?
      true
    end

    # Deeply duplicates and freezes the given value, leaving the original
    # object and its nested structures untouched.
    #
    # @param value [Object] the value to freeze.
    # @return [Object] a deeply frozen copy of the value.
    def self.deep_freeze(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, element), copy|
          copy[deep_freeze(key)] = deep_freeze(element)
        end.freeze
      when Array
        value.map { |element| deep_freeze(element) }.freeze
      when String
        value.dup.freeze
      else
        value
      end
    end
  end
end
