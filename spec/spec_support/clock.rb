# frozen_string_literal: true

module SpecSupport
  class AdvancingClock
    attr_reader :calls

    def initialize(time)
      @time = time
      @calls = 0
    end

    def call
      @calls += 1
      current = @time
      @time += 1
      current
    end
  end
end
