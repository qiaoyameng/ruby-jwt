# frozen_string_literal: true

module JWT
  module Claims
    # @api private
    module Verifier
      POLICY_VERIFIERS = %i[time_policy time].freeze
      LEGACY_TIME_VERIFIERS = %i[exp nbf iat].freeze

      private_constant(:POLICY_VERIFIERS)
      private_constant(:LEGACY_TIME_VERIFIERS)

      VERIFIERS = {
        exp: ->(options) { Claims::Expiration.new(leeway: options.dig(:exp, :leeway)) },
        nbf: ->(options) { Claims::NotBefore.new(leeway: options.dig(:nbf, :leeway)) },
        iss: ->(options) { Claims::Issuer.new(issuers: options[:iss]) },
        iat: ->(options) { Claims::IssuedAt.new(leeway: options.dig(:iat, :leeway)) },
        jti: ->(options) { Claims::JwtId.new(validator: options[:jti]) },
        aud: ->(options) { Claims::Audience.new(expected_audience: options[:aud]) },
        sub: ->(options) { Claims::Subject.new(expected_subject: options[:sub]) },
        crit: ->(options) { Claims::Crit.new(expected_crits: options[:crit]) },
        required: ->(options) { Claims::Required.new(required_claims: options[:required]) },
        numeric: ->(*)        { Claims::Numeric.new },
        time_policy: ->(options) { Claims::TimePolicy.build(options[:time_policy]) },
        time: ->(options) { Claims::TimePolicy.build(options[:time]) }
      }.freeze

      private_constant(:VERIFIERS)

      class << self
        # @api private
        def verify!(context, *options)
          iterate_verifiers(*options) do |verifier, verifier_options|
            verify_one!(context, verifier, verifier_options)
          end
          nil
        end

        # @api private
        def errors(context, *options)
          errors = []
          iterate_verifiers(*options) do |verifier, verifier_options|
            verify_one!(context, verifier, verifier_options)
          rescue ::JWT::ClaimValidationError, ::JWT::MalformedTokenError => e
            # A payload that cannot be decoded has no valid claims either, so the
            # predicate API reports it instead of raising.
            errors << JWT::Claims::Error.new(message: e.message)
          end
          errors
        end

        private

        def iterate_verifiers(*options)
          requests = verifier_requests(options)
          skip_legacy_time_verifiers = requests.any? { |verifier, _options| POLICY_VERIFIERS.include?(verifier) }

          requests.each do |verifier, verifier_options|
            next if skip_legacy_time_verifiers && LEGACY_TIME_VERIFIERS.include?(verifier)

            yield(verifier, verifier_options)
          end
        end

        def verifier_requests(options)
          options.flat_map do |element|
            if element.is_a?(Hash)
              element.keys.map { |key| [key, element] }
            elsif element.is_a?(Claims::TimePolicy)
              [[:time_policy, { time_policy: element }]]
            else
              [[element, {}]]
            end
          end
        end

        def verify_one!(context, verifier, options)
          verifier_builder = VERIFIERS.fetch(verifier) { raise ArgumentError, "#{verifier} not a valid claim verifier" }
          verifier_builder.call(options || {}).verify!(context: context)
        end
      end
    end
  end
end
