# frozen_string_literal: true

module JWT
  module SDJWT
    # Marks a position in an SD-JWT structure whose value remains concealed
    # because no disclosure was provided for its digest.
    class HiddenValue
      attr_reader :path, :digest

      def initialize(path:, digest: nil)
        @path = path.freeze
        @digest = digest
      end

      def ==(other)
        other.is_a?(HiddenValue) && path == other.path && digest == other.digest
      end
      alias eql? ==

      def hash
        [self.class, path, digest].hash
      end

      def inspect
        "#<#{self.class.name} path=#{path.inspect} digest=#{digest.inspect}>"
      end
    end
  end
end
