# frozen_string_literal: true

module JWT
  module SDJWT
    # Resolves SD-JWT digest algorithm names (_sd_alg) to digest classes.
    module DigestAlgorithm
      module_function

      # @param name [String, nil] the _sd_alg value, nil defaults to sha-256.
      # @return [Class] the digest class.
      # @raise [JWT::UnsupportedDigestAlgorithm] if the algorithm is unknown.
      def resolve(name)
        name ||= DEFAULT_DIGEST_ALGORITHM
        DIGEST_ALGORITHMS.fetch(name) do
          raise UnsupportedDigestAlgorithm, "Unsupported SD-JWT digest algorithm #{name.inspect}"
        end
      end
    end
  end
end
