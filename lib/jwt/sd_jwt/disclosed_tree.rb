# frozen_string_literal: true

module JWT
  module SDJWT
    # Builds a nested structure containing only the values reconstructed
    # from disclosures. Array positions not covered by a disclosure are
    # marked with {HiddenValue}.
    class DisclosedTree
      GAP = Object.new.freeze
      private_constant :GAP

      def initialize
        @entries = []
      end

      def add(path, value)
        @entries << [path, value]
      end

      def to_h
        tree = {}
        @entries.each { |path, value| deep_set(tree, path, value) }
        fill_gaps(tree)
      end

      private

      def deep_set(node, path, value)
        key = path.first
        node.fill(GAP, node.size...key) if node.is_a?(Array) && node.size <= key
        return node[key] = value if path.size == 1

        node[key] = path[1].is_a?(Integer) ? [] : {} if node[key].nil? || node[key].equal?(GAP)
        deep_set(node[key], path[1..-1], value)
      end

      def fill_gaps(node)
        case node
        when Hash then node.each_value { |value| fill_gaps(value) }
        when Array then node.map! { |value| value.equal?(GAP) ? HiddenValue.new(path: []) : fill_gaps(value) }
        end
        node
      end
    end
  end
end
