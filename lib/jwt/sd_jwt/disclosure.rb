# frozen_string_literal: true

module JWT
  module SDJWT
    # A single SD-JWT disclosure, parsed from its base64url encoded form.
    #
    # The digest is computed over the raw encoded string exactly as received.
    class Disclosure
      attr_reader :raw, :digest, :salt, :claim_name, :value

      # Parses raw disclosures into a hash keyed by their digest.
      #
      # @raise [JWT::MalformedSDJWTError] if disclosures is not an array.
      # @raise [JWT::DuplicateDisclosureError] if a disclosure appears twice.
      def self.parse_all(raw_disclosures, digest_algorithm:)
        raise MalformedSDJWTError, 'Disclosures must be provided as an array' unless raw_disclosures.is_a?(Array)

        raw_disclosures.each_with_object({}) do |raw, by_digest|
          disclosure = new(raw, digest_algorithm: digest_algorithm)
          raise DuplicateDisclosureError, "Duplicate disclosure #{disclosure.digest}" if by_digest.key?(disclosure.digest)

          by_digest[disclosure.digest] = disclosure
        end
      end

      def initialize(raw, digest_algorithm:)
        raise MalformedDisclosureError, 'Disclosure must be a string' unless raw.is_a?(String)

        @raw = raw
        @digest = Base64.url_encode(digest_algorithm.digest(raw))
        parse(decoded)
      end

      def object_member?
        !claim_name.nil?
      end

      def array_element?
        claim_name.nil?
      end

      private

      def decoded
        JSON.parse(Base64.url_decode(raw))
      rescue Base64DecodeError, ::JSON::ParserError
        raise MalformedDisclosureError, 'Disclosure is not a base64url encoded JSON value'
      end

      def parse(decoded)
        raise MalformedDisclosureError, 'Disclosure must be a JSON array of two or three elements' unless decoded.is_a?(Array) && (2..3).cover?(decoded.size)

        @salt = decoded[0]
        raise MalformedDisclosureError, 'Disclosure salt must be a string' unless @salt.is_a?(String)

        parse_claim(decoded)
      end

      def parse_claim(decoded)
        if decoded.size == 3
          @claim_name = decoded[1]
          raise MalformedDisclosureError, 'Disclosure claim name must be a string' unless @claim_name.is_a?(String)

          @value = decoded[2]
        else
          @value = decoded[1]
        end
      end
    end
  end
end
