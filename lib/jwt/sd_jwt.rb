# frozen_string_literal: true

require 'digest'

module JWT
  # Selective Disclosure for JWTs (SD-JWT) verification.
  #
  # Verifies the issuer-signed JWT and reconstructs the disclosable object
  # members and array elements from the provided disclosures. Digests are
  # always computed over the raw (still base64url encoded) disclosure string.
  #
  # Current limitations of this first version:
  # - only the "sha-256" digest algorithm is supported
  # - SD-JWTs carrying a key-binding JWT are rejected
  module SDJWT
    SD_CLAIM = '_sd'
    SD_ALG_CLAIM = '_sd_alg'
    ARRAY_PLACEHOLDER = '...'
    SUPPORTED_SD_ALG = 'sha-256'
    RESERVED_CLAIM_NAMES = [SD_CLAIM, SD_ALG_CLAIM, ARRAY_PLACEHOLDER].freeze

    class << self
      # Verifies an SD-JWT and returns a {Result} describing the plaintext,
      # disclosed and still hidden claims.
      #
      # @param sdjwt [String] the SD-JWT (issuer-signed JWT followed by
      #   tilde-separated disclosures, without a key-binding JWT).
      # @param key [Object] the key used to verify the issuer signature.
      # @param verify_signature [Boolean] whether to verify the issuer signature.
      # @param options [Hash] additional options passed to {JWT.decode}.
      # @return [Result] the verification result.
      def verify(sdjwt, key = nil, verify_signature = true, options = {}, &keyfinder) # rubocop:disable Style/OptionalBooleanParameter
        issuer_jwt, disclosure_strings = split_segments(sdjwt)
        payload, header = JWT.decode(issuer_jwt, key, verify_signature, options, &keyfinder)
        Verifier.new(payload, header, disclosure_strings).verify
      end

      private

      def split_segments(sdjwt)
        segments = sdjwt.to_s.split('~', -1)
        issuer_jwt = segments.shift
        raise MalformedTokenError, 'SD-JWT must contain at least one ~ separator' if segments.empty?

        raise KeyBindingNotSupportedError, 'SD-JWTs carrying a key-binding JWT are not supported' unless segments.last == ''

        segments.pop

        [issuer_jwt, segments]
      end
    end

    # The outcome of a successful SD-JWT verification.
    #
    # Positions (for {#disclosed} and {#hidden}) are arrays of claim names and
    # array indices describing where in the issuer payload the entry was found.
    class Result
      # @return [Hash] issuer claims merged with the disclosed values. Claims
      #   and array elements that remain hidden are omitted (never guessed).
      attr_reader :payload

      # @return [Hash] the header of the issuer-signed JWT.
      attr_reader :header

      # @return [Hash] only the claims that were plaintext in the issuer-signed
      #   JWT (disclosed and hidden values omitted).
      attr_reader :plaintext

      # @return [Array<Array(Array, Object)>] [path, value] pairs for every
      #   disclosed object member or array element.
      attr_reader :disclosed

      # @return [Array<Array(Array, String)>] [path, digest] pairs for digests
      #   that remain hidden (withheld or decoy digests).
      attr_reader :hidden

      def initialize(payload:, header:, plaintext:, disclosed:, hidden:)
        @payload = payload
        @header = header
        @plaintext = plaintext
        @disclosed = disclosed
        @hidden = hidden
      end
    end

    # A single parsed SD-JWT disclosure.
    # @api private
    class Disclosure
      attr_reader :digest, :claim_name, :value

      def initialize(encoded)
        @digest = Base64.url_encode(::Digest::SHA256.digest(encoded))
        @elements = parse(encoded)
        @claim_name = @elements.size == 3 ? @elements[1] : nil
        @value = @elements[-1]
      end

      def object_member?
        @elements.size == 3
      end

      def array_element?
        @elements.size == 2
      end

      private

      def parse(encoded)
        elements = JWT::JSON.parse(Base64.url_decode(encoded))
        raise MalformedDisclosureError, 'Disclosure must be a JSON array of [salt, value] or [salt, claim name, value]' unless elements.is_a?(Array) && [2, 3].include?(elements.size) && elements.first.is_a?(String)
        raise MalformedDisclosureError, 'Disclosure claim name must be a string' if elements.size == 3 && !elements[1].is_a?(String)

        elements
      rescue Base64DecodeError, ::JSON::ParserError
        raise MalformedDisclosureError, 'Disclosure is not valid base64url encoded JSON'
      end
    end

    # Matches disclosures against the digests in the issuer-signed JWT payload
    # and rebuilds the disclosed claims.
    # @api private
    class Verifier
      def initialize(payload, header, disclosure_strings)
        @payload = payload
        @header = header
        @disclosures = {}
        @consumed = []
        @seen_digests = []
        @disclosed = []
        @hidden = []
        disclosure_strings.each { |string| register(Disclosure.new(string)) }
      end

      def verify
        raise MalformedTokenError, 'SD-JWT payload must be a JSON object' unless @payload.is_a?(Hash)

        check_sd_alg!
        merged, plaintext = process_object(@payload, [])
        check_for_orphans!
        Result.new(payload: merged, header: @header, plaintext: plaintext, disclosed: @disclosed, hidden: @hidden)
      end

      private

      def register(disclosure)
        raise DuplicateDisclosureError, 'The same disclosure was provided more than once' if @disclosures.key?(disclosure.digest)

        @disclosures[disclosure.digest] = disclosure
      end

      def check_sd_alg!
        sd_alg = @payload[SD_ALG_CLAIM]
        return if sd_alg.nil? || sd_alg == SUPPORTED_SD_ALG

        raise UnsupportedSdAlgorithmError, "Unsupported SD-JWT digest algorithm: #{sd_alg.inspect}"
      end

      def check_for_orphans!
        orphans = @disclosures.keys - @consumed
        raise OrphanDisclosureError, "Disclosure digests not referenced by the issuer-signed JWT: #{orphans.join(', ')}" unless orphans.empty?
      end

      def process_value(value, path)
        case value
        when Hash then process_object(value, path)
        when Array then process_array(value, path)
        else [value, value]
        end
      end

      def process_object(object, path)
        merged = {}
        plain = {}
        digests = nil
        object.each do |key, value|
          case key
          when SD_CLAIM then digests = extract_digests(value)
          when SD_ALG_CLAIM then next
          when ARRAY_PLACEHOLDER then raise ReservedClaimError, 'The "..." claim is only allowed as an array element placeholder'
          else
            merged[key], plain[key] = process_value(value, path + [key])
          end
        end
        digests&.each { |digest| disclose_member(digest, merged, path) }
        [merged, plain]
      end

      def process_array(array, path)
        merged = []
        plain = []
        array.each_with_index do |element, index|
          if element.is_a?(Hash) && element.size == 1 && element.key?(ARRAY_PLACEHOLDER)
            disclose_element(element[ARRAY_PLACEHOLDER], merged, path + [index])
          else
            merged_value, plain_value = process_value(element, path + [index])
            merged << merged_value
            plain << plain_value
          end
        end
        [merged, plain]
      end

      def disclose_member(digest, merged, path)
        register_digest(digest)
        disclosure = @disclosures[digest]
        return @hidden << [path, digest] unless disclosure

        name = disclosure.claim_name
        raise MalformedDisclosureError, 'Object member digests require a [salt, claim name, value] disclosure' unless disclosure.object_member?
        raise ReservedClaimError, "The claim name #{name.inspect} is reserved for SD-JWT" if RESERVED_CLAIM_NAMES.include?(name)
        raise ClaimCollisionError, "The disclosed claim #{name.inspect} would override a plaintext claim" if merged.key?(name)

        @consumed << disclosure.digest
        merged[name], = process_value(disclosure.value, path + [name])
        @disclosed << [path + [name], disclosure.value]
      end

      def disclose_element(digest, merged, path)
        raise MalformedTokenError, 'Array placeholder digest must be a string' unless digest.is_a?(String)

        register_digest(digest)
        disclosure = @disclosures[digest]
        return @hidden << [path, digest] unless disclosure

        raise MalformedDisclosureError, 'Array element digests require a [salt, value] disclosure' unless disclosure.array_element?

        @consumed << disclosure.digest
        merged_value, = process_value(disclosure.value, path)
        merged << merged_value
        @disclosed << [path, disclosure.value]
      end

      def extract_digests(value)
        raise MalformedTokenError, 'The _sd claim must be an array of digest strings' unless value.is_a?(Array) && value.all?(String)

        value
      end

      def register_digest(digest)
        raise DuplicateDisclosureError, "The digest #{digest} is referenced more than once in the issuer-signed JWT" if @seen_digests.include?(digest)

        @seen_digests << digest
      end
    end
  end
end
