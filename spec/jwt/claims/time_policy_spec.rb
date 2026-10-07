# frozen_string_literal: true

RSpec.describe JWT::Claims::TimePolicy do
  def verify!(payload, **options)
    described_class.new(**options).verify!(context: JWT::Claims::VerificationContext.new(payload: payload))
  end

  describe '#verify!' do
    it 'uses one clock value for all current-time checks' do
      clock = SpecSupport::AdvancingClock.new(150)
      payload = { 'iat' => 100, 'nbf' => 100, 'exp' => 200 }

      described_class.new(max_issued_age: 50, leeway: 0, clock: clock).verify!(
        context: JWT::Claims::VerificationContext.new(payload: payload)
      )

      expect(clock.calls).to eq(1)
    end

    it 'accepts equality for max issued age' do
      payload = { 'iat' => 100, 'exp' => 200 }

      expect(verify!(payload, max_issued_age: 50, clock: -> { 150 })).to be_nil
    end

    it 'rejects a token one second beyond max issued age' do
      payload = { 'iat' => 99, 'exp' => 200 }

      expect { verify!(payload, max_issued_age: 50, clock: -> { 150 }) }
        .to raise_error(JWT::InvalidIatError, 'iat exceeds maximum issued age')
    end

    it 'applies leeway to max issued age' do
      payload = { 'iat' => 90, 'exp' => 200 }

      expect(verify!(payload, max_issued_age: 50, leeway: 10, clock: -> { 150 })).to be_nil
    end

    it 'accepts equality for max lifetime' do
      payload = { 'iat' => 100, 'exp' => 200 }

      expect(verify!(payload, max_lifetime: 100, leeway: 100, clock: -> { 150 })).to be_nil
    end

    it 'does not apply leeway to max lifetime' do
      payload = { 'iat' => 100, 'exp' => 200 }

      expect { verify!(payload, max_lifetime: 99, leeway: 100, clock: -> { 150 }) }
        .to raise_error(JWT::InvalidPayload, 'Token maximum lifetime exceeded')
    end

    it 'accepts nbf and iat exactly at exp' do
      payload = { 'iat' => 200, 'nbf' => 200, 'exp' => 200 }

      expect(verify!(payload, leeway: 1, clock: -> { 200 })).to be_nil
    end

    it 'reports when iat is later than exp' do
      payload = { 'iat' => 201, 'exp' => 200 }

      expect { verify!(payload, clock: -> { 100 }) }
        .to raise_error(JWT::InvalidPayload, 'iat must not be later than exp')
    end

    it 'reports when nbf is later than exp' do
      payload = { 'nbf' => 201, 'exp' => 200 }

      expect { verify!(payload, clock: -> { 100 }) }
        .to raise_error(JWT::InvalidPayload, 'nbf must not be later than exp')
    end

    it 'uses leeway for exp, nbf and iat comparisons with now' do
      expect(verify!({ 'exp' => 141 }, leeway: 10, clock: -> { 150 })).to be_nil
      expect(verify!({ 'nbf' => 160 }, leeway: 10, clock: -> { 150 })).to be_nil
      expect(verify!({ 'iat' => 160 }, leeway: 10, clock: -> { 150 })).to be_nil
    end

    it 'rejects values outside the leeway boundary' do
      expect { verify!({ 'exp' => 140 }, leeway: 10, clock: -> { 150 }) }
        .to raise_error(JWT::ExpiredSignature, 'Signature has expired')
      expect { verify!({ 'nbf' => 161 }, leeway: 10, clock: -> { 150 }) }
        .to raise_error(JWT::ImmatureSignature, 'Signature nbf has not been reached')
      expect { verify!({ 'iat' => 161 }, leeway: 10, clock: -> { 150 }) }
        .to raise_error(JWT::InvalidIatError, 'Invalid iat')
    end

    it 'treats required fields as missing separately from numeric zero' do
      expect { verify!({ 'exp' => 0 }, required_claims: %w[exp iat], clock: -> { 100 }) }
        .to raise_error(JWT::MissingRequiredClaim, 'Missing required claim iat')

      expect { verify!({ 'exp' => 0 }, required_claims: ['exp'], clock: -> { 100 }) }
        .to raise_error(JWT::ExpiredSignature)
    end

    it 'reports a missing required claim before reading the clock' do
      clock_calls = 0

      expect do
        verify!({}, required_claims: ['exp'], clock: -> { clock_calls += 1 })
      end.to raise_error(JWT::MissingRequiredClaim, 'Missing required claim exp')

      expect(clock_calls).to eq(0)
    end

    it 'accepts zero for duration limits and leeway' do
      payload = { 'iat' => 100, 'exp' => 100 }

      expect(verify!(payload, max_issued_age: 0, max_lifetime: 0, leeway: 1, clock: -> { 100 })).to be_nil
    end

    %w[exp iat nbf].each do |claim|
      it "rejects a string #{claim} claim" do
        expect { verify!({ claim => '100' }, clock: -> { 100 }) }
          .to raise_error(JWT::InvalidPayload, "#{claim} claim must be a finite Numeric value")
      end

      [Float::INFINITY, -Float::INFINITY, Float::NAN].each do |value|
        it "rejects #{value.inspect} for #{claim}" do
          expect { verify!({ claim => value }, clock: -> { 100 }) }
            .to raise_error(JWT::InvalidPayload, "#{claim} claim must be a finite Numeric value")
        end
      end
    end

    it 'rejects a non-finite clock value' do
      expect { verify!({}, clock: -> { Float::INFINITY }) }
        .to raise_error(JWT::InvalidPayload, 'clock must be a finite Numeric value')
    end

    it 'can be configured with a Hash through the generic claims verifier' do
      payload = { 'exp' => 200 }

      expect(JWT::Claims.verify_payload!(payload, time_policy: { leeway: 0, clock: -> { 100 } })).to be_nil
    end

    it 'can be passed directly to the generic claims verifier' do
      payload = { 'exp' => 200 }
      policy = described_class.new(clock: -> { 100 })

      expect(JWT::Claims.verify_payload!(payload, policy)).to be_nil
    end

    it 'does not run legacy time verifiers together with a time policy' do
      clock = SpecSupport::AdvancingClock.new(100)
      payload = { 'exp' => 200 }

      JWT::Claims.verify_payload!(payload, :exp, time_policy: { clock: clock })

      expect(clock.calls).to eq(1)
    end
  end

  describe '.new' do
    [
      [:max_issued_age, -1],
      [:max_lifetime, -1],
      [:leeway, -1],
      [:max_issued_age, '1'],
      [:max_lifetime, Float::INFINITY]
    ].each do |name, value|
      it "rejects #{value.inspect} for #{name}" do
        expect { described_class.new(name => value) }
          .to raise_error(ArgumentError)
      end
    end

    it 'rejects a non-array required list' do
      expect { described_class.new(required_claims: 'exp') }
        .to raise_error(ArgumentError, 'required_claims must be an Array')
    end

    it 'rejects a non-callable clock' do
      expect { described_class.new(clock: 'now') }
        .to raise_error(ArgumentError, 'clock must respond to #call or #now')
    end

    it 'rejects conflicting aliases' do
      expect do
        described_class.new(max_issued_age: 1, maximum_issued_age: 2)
      end.to raise_error(ArgumentError, 'conflicting values given for max_issued_age')
    end
  end
end
