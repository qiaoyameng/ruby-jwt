# frozen_string_literal: true

module JWT
  module SDJWT
    # The outcome of verifying an SD-JWT and its disclosures.
    #
    # Positions that remain concealed are never fabricated: hidden object
    # members are simply absent from {#payload} and hidden array elements are
    # represented by {HiddenValue} markers.
    class Result
      # @return [Hash] the issuer claims with disclosures applied; concealed
      #   positions are omitted or marked with {HiddenValue}.
      attr_reader :payload

      # @return [Hash] the issuer JWT payload exactly as decoded, before any
      #   disclosure was applied.
      attr_reader :plaintext

      # @return [Hash] a nested structure containing only the values
      #   reconstructed from disclosures.
      attr_reader :disclosed

      # @return [Array<HiddenValue>] the positions that remain concealed.
      attr_reader :hidden

      # @return [Hash] the issuer JWT header.
      attr_reader :header

      def initialize(payload:, plaintext:, disclosed:, hidden:, header: nil)
        @payload = payload
        @plaintext = plaintext
        @disclosed = disclosed
        @hidden = hidden
        @header = header
      end
    end
  end
end
