# frozen_string_literal: true

require 'digest'

module JWT
  # @private
  class EncodedToken
    # Immutable outcome of verifying an EncodedToken via EncodedToken#verify_result.
    #
    # A successful result snapshots the exact token state that was verified:
    # the token string, the signing input, the signature bytes, the header,
    # the payload, the algorithm that matched and the claim checks that were
    # performed, all bound to the time of verification. All nested structures
    # are deep frozen, so the result cannot be altered through any reference
    # after it has been returned, and later changes to the token or to the
    # objects passed to it do not affect the result.
    class VerifyResult
      EMPTY_CLAIMS = [].freeze

      private_constant(:EMPTY_CLAIMS)

      class << self
        # @api private
        def success(attributes)
          new(deep_freeze(attributes).merge(error: nil))
        end

        # @api private
        def failure(error:, verified_at:)
          new(verified_claims: EMPTY_CLAIMS, verified_at: verified_at, error: error)
        end

        private

        def deep_freeze(value)
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

      # Returns the token string as it was when it was verified, nil for a failed verification.
      attr_reader :jwt

      # Returns the parsed header as a deep frozen Hash, nil for a failed verification.
      #
      # The header is integrity protected by the signature, but individual
      # claims are only validated when listed in {#verified_claims}.
      attr_reader :header

      # Returns the verified payload as a deep frozen Hash, nil for a failed verification.
      #
      # The payload is integrity protected by the signature, but individual
      # claims are only validated when listed in {#verified_claims}.
      attr_reader :payload

      # Returns the exact signature bytes that were verified, nil for a failed verification.
      attr_reader :signature

      # Returns the signing input that was verified, nil for a failed verification.
      attr_reader :signing_input

      # Returns the algorithm that successfully verified the signature, nil for a failed verification.
      attr_reader :algorithm

      # Returns the names of the claim checks that were performed and passed.
      # Claims that were not checked are not included.
      attr_reader :verified_claims

      # Returns the time the verification was performed.
      attr_reader :verified_at

      # Returns the error of a failed verification, nil for a successful one.
      attr_reader :error

      # Returns the SHA-256 hex digest of the verified signature bytes,
      # nil for a failed verification.
      attr_reader :signature_digest

      def initialize(attributes)
        @jwt = attributes[:jwt]
        @header = attributes[:header]
        @payload = attributes[:payload]
        @signature = attributes[:signature]
        @signature_digest = @signature && Digest::SHA256.hexdigest(@signature).freeze
        @signing_input = attributes[:signing_input]
        @algorithm = attributes[:algorithm]
        @verified_claims = attributes[:verified_claims]
        @verified_at = attributes[:verified_at]
        @error = attributes[:error]
        freeze
      end

      # Returns whether the signature and the requested claims were verified.
      #
      # @return [Boolean] whether the verification succeeded.
      def verified?
        @error.nil?
      end

      alias success? verified?

      # Returns whether the verification failed.
      #
      # @return [Boolean] whether the verification failed.
      def failure?
        !verified?
      end

      # Returns whether the given claim was checked and passed validation.
      # Claims whose checks were not requested are not considered verified.
      #
      # @param name [String, Symbol] the name of the claim.
      # @return [Boolean] whether the claim was verified.
      def claim_verified?(name)
        verified_claims.include?(name.to_sym)
      end
    end
  end
end
