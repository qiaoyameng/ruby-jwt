# frozen_string_literal: true

module JWT
  module SDJWT
    # Reconstructs the selectively disclosable claims of an issuer signed
    # SD-JWT payload from the given disclosures: object members via digests
    # in +_sd+ arrays, array elements via +{"...": digest}+ placeholders.
    # Digests without a matching disclosure (including decoys) stay concealed.
    class Verifier
      def initialize(payload, disclosures, header: nil)
        @payload = payload
        @header = header
        @raw_disclosures = disclosures
        @used_digests = []
        @hidden = []
        @disclosed_tree = DisclosedTree.new
      end

      def verify
        sd_alg = @payload[SD_ALG_KEY] if @payload.is_a?(Hash)
        @disclosures = Disclosure.parse_all(@raw_disclosures, digest_algorithm: DigestAlgorithm.resolve(sd_alg))
        merged = process_value(@payload, [])
        reject_orphan_disclosures!
        Result.new(payload: merged,
                   plaintext: @payload,
                   disclosed: @disclosed_tree.to_h,
                   hidden: @hidden,
                   header: @header)
      end

      private

      def process_value(value, path)
        case value
        when Hash then process_object(value, path)
        when Array then process_array(value, path)
        else value
        end
      end

      def process_object(object, path)
        result = {}
        object.each do |key, member|
          next if key == SD_KEY
          next if key == SD_ALG_KEY && DigestAlgorithm.resolve(member)

          result[key] = process_value(member, path + [key])
        end
        apply_object_disclosures(object, result, path)
        result
      end

      def apply_object_disclosures(object, result, path)
        sd_digests(object).each do |digest|
          disclosure = @disclosures[digest]
          if disclosure.nil?
            @hidden << HiddenValue.new(path: path, digest: digest)
            next
          end
          claim_name = object_member_claim_name(disclosure)
          use_disclosure!(disclosure)
          raise DisclosedClaimConflictError, "Disclosure would overwrite existing claim #{claim_name.inspect}" if result.key?(claim_name)

          disclosed_value = process_value(disclosure.value, path + [claim_name])
          @disclosed_tree.add(path + [claim_name], disclosed_value)
          result[claim_name] = disclosed_value
        end
      end

      def sd_digests(object)
        digests = object[SD_KEY]
        return [] if digests.nil?

        raise MalformedSDJWTError, 'The _sd claim must be an array of digest strings' unless digests.is_a?(Array) && digests.all?(String)

        digests
      end

      def object_member_claim_name(disclosure)
        raise MalformedDisclosureError, 'Array element disclosure cannot disclose an object member' unless disclosure.object_member?

        claim_name = disclosure.claim_name
        raise DisclosedClaimConflictError, "Disclosure uses reserved claim name #{claim_name.inspect}" if RESERVED_CLAIM_NAMES.include?(claim_name)

        claim_name
      end

      def process_array(array, path)
        array.each_with_index.map do |element, index|
          element_path = path + [index]
          if element.is_a?(Hash) && element.key?(ARRAY_PLACEHOLDER_KEY)
            process_placeholder(element, element_path)
          else
            process_value(element, element_path)
          end
        end
      end

      def process_placeholder(placeholder, path)
        raise MalformedSDJWTError, 'Array placeholder objects must only contain the "..." key' unless placeholder.size == 1

        digest = placeholder[ARRAY_PLACEHOLDER_KEY]
        raise MalformedSDJWTError, 'Array placeholder digest must be a string' unless digest.is_a?(String)

        disclosure = @disclosures[digest]
        if disclosure.nil?
          hidden = HiddenValue.new(path: path, digest: digest)
          @hidden << hidden
          return hidden
        end

        raise MalformedDisclosureError, 'Object member disclosure cannot disclose an array element' if disclosure.object_member?

        use_disclosure!(disclosure)
        disclosed_value = process_value(disclosure.value, path)
        @disclosed_tree.add(path, disclosed_value)
        disclosed_value
      end

      def use_disclosure!(disclosure)
        raise DuplicateDisclosureError, "Disclosure #{disclosure.digest} is used more than once" if @used_digests.include?(disclosure.digest)

        @used_digests << disclosure.digest
      end

      def reject_orphan_disclosures!
        orphans = @disclosures.keys - @used_digests
        return if orphans.empty?

        raise OrphanDisclosureError, "No matching digest found for disclosures: #{orphans.join(', ')}"
      end
    end
  end
end
