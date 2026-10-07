# frozen_string_literal: true

module JWT
  module Claims
    # Context class to contain the data passed to individual claim validators
    #
    # @api private
    VerificationContext = Struct.new(:payload, keyword_init: true)

    # Verifiers to support the ::JWT.decode method
    #
    # @api private
    module DecodeVerifier
      TIME_POLICY_KEY = :time_policy
      LEGACY_TIME_VERIFIERS = %i[verify_expiration verify_not_before verify_iat].freeze

      private_constant(:TIME_POLICY_KEY)
      private_constant(:LEGACY_TIME_VERIFIERS)

      VERIFIERS = {
        verify_expiration: ->(options) { Claims::Expiration.new(leeway: options[:exp_leeway] || options[:leeway]) },
        verify_not_before: ->(options) { Claims::NotBefore.new(leeway: options[:nbf_leeway] || options[:leeway]) },
        verify_iss: ->(options) { options[:iss] && Claims::Issuer.new(issuers: options[:iss]) },
        verify_iat: ->(options) { Claims::IssuedAt.new(leeway: options[:verify_iat].is_a?(Hash) ? options[:verify_iat][:leeway] : nil) },
        verify_jti: ->(options) { Claims::JwtId.new(validator: options[:verify_jti]) },
        verify_aud: ->(options) { options[:aud] && Claims::Audience.new(expected_audience: options[:aud]) },
        verify_sub: ->(options) { options[:sub] && Claims::Subject.new(expected_subject: options[:sub]) },
        required_claims: ->(options) { Claims::Required.new(required_claims: options[:required_claims]) }
      }.freeze

      private_constant(:VERIFIERS)

      class << self
        # @api private
        def verify!(payload, options)
          time_policy = options[TIME_POLICY_KEY]
          verify_time_policy!(payload, time_policy)

          each_enabled_verifier(options, time_policy) do |verifier_builder|
            verifier_builder&.call(options)&.verify!(context: VerificationContext.new(payload: payload))
          end
          nil
        end

        private

        def verify_time_policy!(payload, time_policy)
          return unless time_policy

          policy = Claims::TimePolicy.build(time_policy)
          policy.verify!(context: VerificationContext.new(payload: payload))
        end

        def each_enabled_verifier(options, time_policy)
          VERIFIERS.each do |key, verifier_builder|
            next if time_policy && LEGACY_TIME_VERIFIERS.include?(key)
            next unless options[key] || options[key.to_s]

            yield(verifier_builder)
          end
        end
      end
    end
  end
end
