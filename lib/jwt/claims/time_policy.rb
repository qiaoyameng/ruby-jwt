# frozen_string_literal: true

module JWT
  module Claims
    # Validates the temporal relationships and validity period of a JWT.
    class TimePolicy # rubocop:disable Metrics/ClassLength
      TIME_CLAIMS = %w[exp iat nbf].freeze

      private_constant(:TIME_CLAIMS)

      # Builds a policy from a policy instance or a Hash of policy options.
      def self.build(policy)
        return policy if policy.is_a?(TimePolicy)
        return new(**policy.transform_keys(&:to_sym)) if policy.is_a?(Hash)

        raise ArgumentError, 'time_policy must be a JWT::Claims::TimePolicy or a Hash'
      end

      # @param required_claims [Array<String, Symbol>] claims that must be present
      # @param max_issued_age [Numeric] maximum accepted current age based on `iat`
      # @param max_lifetime [Numeric] maximum accepted value of `exp - iat`
      # @param leeway [Numeric] leeway in seconds for comparisons with the current time
      # @param clock [#call, #now] source of the current verification time
      def initialize(required_claims: nil, # rubocop:disable Metrics/ParameterLists
                     required: nil,
                     max_issued_age: nil,
                     maximum_issued_age: nil,
                     max_lifetime: nil,
                     maximum_lifetime: nil,
                     leeway: 0,
                     clock: Time)
        @required_claims = validate_required_claims(select_option(required_claims, required, :required_claims) || [])
        @max_issued_age = validate_optional_duration(select_option(max_issued_age, maximum_issued_age, :max_issued_age), :max_issued_age)
        @max_lifetime = validate_optional_duration(select_option(max_lifetime, maximum_lifetime, :max_lifetime), :max_lifetime)
        @leeway = validate_duration(leeway, :leeway)
        @clock = validate_clock(clock)
      end

      # @param context [Object] the context containing the JWT payload
      # @raise [JWT::ClaimValidationError] if a temporal claim or relationship is invalid
      # @return [nil]
      def verify!(context:, **_args)
        payload = context.payload.is_a?(Hash) ? context.payload : {}

        verify_required_claims!(payload)
        now = finite_number(call_clock, 'clock')
        values = read_claim_values(payload)

        verify_relationships!(values)
        verify_lifetime!(values)
        verify_current_time!(values, now)

        nil
      end

      private

      attr_reader :required_claims, :max_issued_age, :max_lifetime, :leeway, :clock

      def read_claim_values(payload)
        TIME_CLAIMS.each_with_object({}) do |claim, memo|
          memo[claim] = claim_value(payload, claim)
        end
      end

      def verify_required_claims!(payload)
        required_claims.each do |claim|
          next if payload.key?(claim) || payload.key?(claim.to_sym)

          raise JWT::MissingRequiredClaim, "Missing required claim #{claim}"
        end
      end

      def claim_value(payload, claim)
        return nil unless payload.key?(claim) || payload.key?(claim.to_sym)

        value = payload.key?(claim) ? payload[claim] : payload[claim.to_sym]
        finite_number(value, "#{claim} claim")
      end

      def verify_relationships!(values)
        exp = values['exp']

        raise JWT::InvalidPayload, 'iat must not be later than exp' if relationship_violated?(values['iat'], exp)
        raise JWT::InvalidPayload, 'nbf must not be later than exp' if relationship_violated?(values['nbf'], exp)
      end

      def relationship_violated?(time, exp)
        time && exp && time > exp
      end

      def verify_lifetime!(values)
        iat = values['iat']
        exp = values['exp']

        return unless iat && exp

        lifetime = exp - iat
        raise JWT::InvalidPayload, 'Token maximum lifetime exceeded' if max_lifetime && lifetime > max_lifetime
      end

      def verify_current_time!(values, now)
        verify_expiration!(values['exp'], now)
        verify_not_before!(values['nbf'], now)
        verify_issued_at!(values['iat'], now)
      end

      def verify_expiration!(exp, now)
        return unless exp && now >= exp + leeway

        raise JWT::ExpiredSignature, 'Signature has expired'
      end

      def verify_not_before!(nbf, now)
        return unless nbf && nbf > now + leeway

        raise JWT::ImmatureSignature, 'Signature nbf has not been reached'
      end

      def verify_issued_at!(iat, now)
        return unless iat

        raise JWT::InvalidIatError, 'Invalid iat' if iat > now + leeway
        return unless max_issued_age && now - iat > max_issued_age + leeway

        raise JWT::InvalidIatError, 'iat exceeds maximum issued age'
      end

      def call_clock
        clock.respond_to?(:call) ? clock.call : clock.now
      end

      def finite_number(value, description)
        number = value.is_a?(::Time) ? value.to_f : value
        raise JWT::InvalidPayload, "#{description} must be a finite Numeric value" unless finite_real_number?(number)

        number.to_f
      end

      def finite_real_number?(value)
        value.is_a?(::Numeric) && value.respond_to?(:finite?) && value.finite? && value.real?
      end

      def validate_required_claims(value)
        raise ArgumentError, 'required_claims must be an Array' unless value.is_a?(Array)

        value.map do |claim|
          next claim.to_s if claim.is_a?(::String) || claim.is_a?(::Symbol)

          raise ArgumentError, 'required_claims must contain only Strings or Symbols'
        end.freeze
      end

      def validate_optional_duration(value, name)
        return nil if value.nil?

        validate_duration(value, name)
      end

      def validate_duration(value, name)
        number = option_number(value, name)
        raise ArgumentError, "#{name} must be greater than or equal to 0" if number.negative?

        number
      end

      def option_number(value, name)
        raise ArgumentError, "#{name} must be a finite Numeric value" unless finite_real_number?(value)

        value.to_f
      end

      def validate_clock(value)
        return value if value.respond_to?(:call) || value.respond_to?(:now)

        raise ArgumentError, 'clock must respond to #call or #now'
      end

      def select_option(value, alternate, name)
        raise ArgumentError, "conflicting values given for #{name}" if !value.nil? && !alternate.nil? && value != alternate

        value.nil? ? alternate : value
      end
    end
  end
end
