# frozen_string_literal: true

module JWT
  module Claims
    # The TimePolicy class provides a reusable time based validation policy for
    # the 'exp', 'iat' and 'nbf' claims of a JWT token.
    #
    # In addition to validating each claim against the current time, the policy
    # can enforce a maximum token age (seconds since 'iat'), a maximum token
    # lifetime ('exp - iat') and the relations 'nbf <= exp' and 'iat <= exp'.
    # Claims that must be present are declared explicitly via 'required'.
    #
    # The current time is fetched exactly once per verification from the
    # injectable clock, so all comparisons within one verification use the
    # same moment in time. The leeway only relaxes comparisons against the
    # current time, never the token's own maximum lifetime.
    class TimePolicy
      # The time claims the policy operates on.
      CLAIMS = %w[exp iat nbf].freeze

      private_constant(:CLAIMS)

      # Initializes a new TimePolicy instance.
      #
      # @param required [Array<String, Symbol>] the time claims ('exp', 'iat', 'nbf') that must be present in the payload.
      # @param max_age [Numeric, nil] the maximum allowed age of the token in seconds ('now - iat'). The leeway relaxes this comparison.
      # @param max_lifetime [Numeric, nil] the maximum allowed lifetime of the token in seconds ('exp - iat'). The leeway does not relax this limit.
      # @param leeway [Numeric] the leeway in seconds applied to comparisons against the current time. Default: 0.
      # @param clock [#call] a callable returning the current time as a Numeric or Time. Default: '-> { Time.now }'.
      def initialize(required: [], max_age: nil, max_lifetime: nil, leeway: 0, clock: -> { Time.now })
        @required     = validate_required(required)
        @max_age      = validate_duration(:max_age, max_age, allow_nil: true)
        @max_lifetime = validate_duration(:max_lifetime, max_lifetime, allow_nil: true)
        @leeway       = validate_duration(:leeway, leeway)
        @clock        = validate_clock(clock)
      end

      # Verifies the time claims of the JWT token against the policy.
      #
      # @param context [Object] the context containing the JWT payload.
      # @param _args [Hash] additional arguments (not used).
      # @raise [JWT::MissingRequiredClaim] if a required claim is missing.
      # @raise [JWT::InvalidPayload] if a present claim is not a finite Numeric.
      # @raise [JWT::ExpiredSignature] if the token has expired.
      # @raise [JWT::ImmatureSignature] if the 'nbf' claim has not been reached.
      # @raise [JWT::InvalidIatError] if the 'iat' claim is in the future.
      # @raise [JWT::InvalidTimePolicyError] if a relation, the maximum age or the maximum lifetime is violated.
      # @return [nil]
      def verify!(context:, **_args)
        return unless context.payload.is_a?(Hash)

        now = current_time
        verify_required!(context.payload)
        claims = extract_claims(context.payload)
        verify_relations!(claims)
        verify_current_time!(claims, now)
        verify_max_age!(claims, now)
        verify_max_lifetime!(claims)
        nil
      end

      private

      attr_reader :required, :max_age, :max_lifetime, :leeway, :clock

      def validate_required(required)
        claims = Array(required).map(&:to_s)
        unknown = claims - CLAIMS
        raise ArgumentError, "required contains unsupported time claims: #{unknown.join(', ')}" unless unknown.empty?

        claims
      end

      def validate_duration(name, value, allow_nil: false)
        return nil if allow_nil && value.nil?
        return value if value.is_a?(::Numeric) && value.finite? && value >= 0

        raise ArgumentError, "#{name} must be a non-negative finite Numeric"
      end

      def validate_clock(clock)
        return clock if clock.respond_to?(:call)

        raise ArgumentError, 'clock must respond to call'
      end

      def current_time
        now = clock.call
        now = now.to_f if now.is_a?(::Time)
        return now if now.is_a?(::Numeric) && now.finite?

        raise ArgumentError, 'clock must return a finite Numeric or Time'
      end

      def verify_required!(payload)
        required.each do |claim|
          next if payload.key?(claim)

          raise JWT::MissingRequiredClaim, "Missing required claim #{claim}"
        end
      end

      def extract_claims(payload)
        CLAIMS.each_with_object({}) do |claim, claims|
          next unless payload.key?(claim)

          value = payload[claim]
          raise JWT::InvalidPayload, "#{claim} claim must be a Numeric value but it is a #{value.class}" unless value.is_a?(::Numeric)
          raise JWT::InvalidPayload, "#{claim} claim must be a finite Numeric value" unless value.finite?

          claims[claim] = value
        end
      end

      def verify_relations!(claims)
        exp = claims['exp']
        return unless exp

        nbf = claims['nbf']
        raise JWT::InvalidTimePolicyError, "nbf (#{nbf}) is later than exp (#{exp})" if nbf && nbf > exp

        iat = claims['iat']
        raise JWT::InvalidTimePolicyError, "iat (#{iat}) is later than exp (#{exp})" if iat && iat > exp
      end

      def verify_current_time!(claims, now)
        exp = claims['exp']
        raise JWT::ExpiredSignature, 'Signature has expired' if exp && exp <= now - leeway

        nbf = claims['nbf']
        raise JWT::ImmatureSignature, 'Signature nbf has not been reached' if nbf && nbf > now + leeway

        iat = claims['iat']
        raise JWT::InvalidIatError, 'Invalid iat' if iat && iat > now + leeway
      end

      def verify_max_age!(claims, now)
        iat = claims['iat']
        return unless max_age && iat
        return if now - iat <= max_age + leeway

        raise JWT::InvalidTimePolicyError, "token age exceeds the maximum of #{max_age} seconds"
      end

      def verify_max_lifetime!(claims)
        iat = claims['iat']
        exp = claims['exp']
        return unless max_lifetime && iat && exp
        return if exp - iat <= max_lifetime

        raise JWT::InvalidTimePolicyError, "token lifetime exceeds the maximum of #{max_lifetime} seconds"
      end
    end
  end
end
