# frozen_string_literal: true

module SpecSupport
  # A fake clock that advances by `step` on every call, so that reading the
  # current time more than once per verification is observable.
  class AdvancingClock
    attr_reader :calls

    def initialize(start, step: 1)
      @now   = start
      @step  = step
      @calls = 0
    end

    def call
      @calls += 1
      @now.tap { @now += @step }
    end
  end
end
