# frozen_string_literal: true

RSpec.describe JWT::Claims::TimePolicy do
  let(:clock) { SpecSupport::AdvancingClock.new(110) }
  let(:policy_options) { { clock: clock } }
  let(:payload) { {} }

  subject(:verify!) { described_class.new(**policy_options).verify!(context: SpecSupport::Token.new(payload: payload)) }

  context 'when payload is not a Hash' do
    let(:payload) { 'beautyexperts_nbf_iat' }

    it 'passes validation' do
      verify!
    end
  end

  describe 'required claims' do
    let(:policy_options) { super().merge(required: %w[iat exp]) }

    context 'when a required claim is missing' do
      let(:payload) { { 'iat' => 100 } }

      it 'raises JWT::MissingRequiredClaim' do
        expect { verify! }.to raise_error(JWT::MissingRequiredClaim, 'Missing required claim exp')
      end
    end

    context 'when a required claim is present with a zero value' do
      let(:payload) { { 'iat' => 0, 'exp' => 1_000 } }

      it 'is treated as present and passes validation' do
        verify!
      end
    end

    context 'when a required claim is zero and checked against the current time' do
      let(:policy_options) { super().merge(max_age: 10) }
      let(:payload) { { 'iat' => 0, 'exp' => 1_000 } }

      it 'uses the zero value instead of treating it as missing' do
        expect { verify! }.to raise_error(JWT::InvalidTimePolicyError, /token age/)
      end
    end
  end

  describe 'claim value types' do
    context 'when a claim is a String' do
      let(:payload) { { 'exp' => '120' } }

      it 'raises JWT::InvalidPayload' do
        expect { verify! }.to raise_error(JWT::InvalidPayload, 'exp claim must be a Numeric value but it is a String')
      end
    end

    context 'when a claim is not a finite number' do
      let(:payload) { { 'iat' => Float::INFINITY } }

      it 'raises JWT::InvalidPayload' do
        expect { verify! }.to raise_error(JWT::InvalidPayload, 'iat claim must be a finite Numeric value')
      end
    end

    context 'when a claim is NaN' do
      let(:payload) { { 'nbf' => Float::NAN } }

      it 'raises JWT::InvalidPayload' do
        expect { verify! }.to raise_error(JWT::InvalidPayload, 'nbf claim must be a finite Numeric value')
      end
    end
  end

  describe 'relation checks' do
    context 'when nbf is later than exp' do
      let(:payload) { { 'nbf' => 200, 'exp' => 150 } }

      it 'raises JWT::InvalidTimePolicyError pointing at the violated relation' do
        expect { verify! }.to raise_error(JWT::InvalidTimePolicyError, 'nbf (200) is later than exp (150)')
      end
    end

    context 'when iat is later than exp' do
      let(:payload) { { 'iat' => 200, 'exp' => 150 } }

      it 'raises JWT::InvalidTimePolicyError pointing at the violated relation' do
        expect { verify! }.to raise_error(JWT::InvalidTimePolicyError, 'iat (200) is later than exp (150)')
      end
    end

    context 'when nbf and iat are not later than exp' do
      let(:payload) { { 'iat' => 100, 'nbf' => 105, 'exp' => 1_000 } }

      it 'passes validation' do
        verify!
      end
    end
  end

  describe 'comparisons against the current time' do
    context 'when the token is expired' do
      let(:payload) { { 'exp' => 109 } }

      it 'raises JWT::ExpiredSignature' do
        expect { verify! }.to raise_error(JWT::ExpiredSignature)
      end
    end

    context 'when the token is expired within the leeway' do
      let(:policy_options) { super().merge(leeway: 5) }
      let(:payload) { { 'exp' => 106 } }

      it 'passes validation' do
        verify!
      end
    end

    context 'when nbf has not been reached' do
      let(:payload) { { 'nbf' => 111 } }

      it 'raises JWT::ImmatureSignature' do
        expect { verify! }.to raise_error(JWT::ImmatureSignature)
      end
    end

    context 'when iat is in the future' do
      let(:payload) { { 'iat' => 111 } }

      it 'raises JWT::InvalidIatError' do
        expect { verify! }.to raise_error(JWT::InvalidIatError)
      end
    end
  end

  describe 'max_age' do
    let(:policy_options) { super().merge(max_age: 10) }

    context 'when the token age is exactly the maximum' do
      let(:payload) { { 'iat' => 100 } }

      it 'passes validation reading the clock exactly once' do
        verify!
        expect(clock.calls).to eq(1)
      end
    end

    context 'when the token is older than the maximum age' do
      let(:payload) { { 'iat' => 99 } }

      it 'raises JWT::InvalidTimePolicyError' do
        expect { verify! }.to raise_error(JWT::InvalidTimePolicyError, 'token age exceeds the maximum of 10 seconds')
      end
    end

    context 'when the age exceeds the maximum within the leeway' do
      let(:policy_options) { super().merge(leeway: 10) }
      let(:payload) { { 'iat' => 95 } }

      it 'passes validation' do
        verify!
      end
    end

    context 'when iat is missing and not required' do
      let(:payload) { { 'exp' => 1_000 } }

      it 'passes validation' do
        verify!
      end
    end
  end

  describe 'max_lifetime' do
    let(:policy_options) { super().merge(max_lifetime: 100) }

    context 'when the token lifetime exceeds the maximum' do
      let(:payload) { { 'iat' => 100, 'exp' => 201 } }

      it 'raises JWT::InvalidTimePolicyError' do
        expect { verify! }.to raise_error(JWT::InvalidTimePolicyError, 'token lifetime exceeds the maximum of 100 seconds')
      end
    end

    context 'when the token lifetime exceeds the maximum but leeway is given' do
      let(:policy_options) { super().merge(leeway: 1_000) }
      let(:payload) { { 'iat' => 100, 'exp' => 201 } }

      it 'still raises JWT::InvalidTimePolicyError as leeway does not relax the lifetime' do
        expect { verify! }.to raise_error(JWT::InvalidTimePolicyError, /token lifetime/)
      end
    end

    context 'when the token lifetime is exactly the maximum' do
      let(:payload) { { 'iat' => 100, 'exp' => 200 } }

      it 'passes validation' do
        verify!
      end
    end
  end

  describe 'single clock reading per verification' do
    let(:policy_options) { super().merge(required: %w[iat exp nbf], max_age: 10, max_lifetime: 20, leeway: 0) }
    let(:payload) { { 'iat' => 100, 'nbf' => 105, 'exp' => 120 } }

    it 'reads the clock exactly once for all checks' do
      verify!
      expect(clock.calls).to eq(1)
    end
  end

  describe 'policy parameter validation' do
    it 'rejects a negative max_age' do
      expect { described_class.new(max_age: -1) }.to raise_error(ArgumentError, 'max_age must be a non-negative finite Numeric')
    end

    it 'rejects a non-numeric max_age' do
      expect { described_class.new(max_age: '10') }.to raise_error(ArgumentError, 'max_age must be a non-negative finite Numeric')
    end

    it 'rejects an infinite max_lifetime' do
      expect { described_class.new(max_lifetime: Float::INFINITY) }.to raise_error(ArgumentError, 'max_lifetime must be a non-negative finite Numeric')
    end

    it 'rejects a negative leeway' do
      expect { described_class.new(leeway: -5) }.to raise_error(ArgumentError, 'leeway must be a non-negative finite Numeric')
    end

    it 'rejects unknown required claims' do
      expect { described_class.new(required: %w[exp foo]) }.to raise_error(ArgumentError, 'required contains unsupported time claims: foo')
    end

    it 'rejects a clock that is not callable' do
      expect { described_class.new(clock: 110) }.to raise_error(ArgumentError, 'clock must respond to call')
    end

    it 'rejects a clock returning a non-numeric value' do
      policy = described_class.new(clock: -> { 'now' })
      expect { policy.verify!(context: SpecSupport::Token.new(payload: {})) }.to raise_error(ArgumentError, 'clock must return a finite Numeric or Time')
    end
  end

  describe 'decode and EncodedToken entry points' do
    let(:key) { 'secret' }
    let(:payload) { { 'iat' => 100, 'exp' => 250 } }
    let(:token) { JWT.encode(payload, key, 'HS256') }
    let(:policy) { { required: %w[iat exp], max_lifetime: 100, clock: -> { 110 } } }

    context 'when the policy is violated' do
      it 'raises the same error via JWT.decode and EncodedToken' do
        expect do
          JWT.decode(token, key, true, verify_expiration: false, verify_time_policy: policy, algorithm: 'HS256')
        end.to raise_error(JWT::InvalidTimePolicyError, 'token lifetime exceeds the maximum of 100 seconds')

        expect do
          JWT::EncodedToken.new(token).verify_claims!(time_policy: policy)
        end.to raise_error(JWT::InvalidTimePolicyError, 'token lifetime exceeds the maximum of 100 seconds')
      end
    end

    context 'when the policy is satisfied' do
      let(:payload) { { 'iat' => 100, 'exp' => 200 } }

      it 'passes via JWT.decode and EncodedToken' do
        expect(JWT.decode(token, key, true, verify_expiration: false, verify_time_policy: policy, algorithm: 'HS256').first).to include('iat' => 100)

        encoded_token = JWT::EncodedToken.new(token)
        encoded_token.verify_signature!(algorithm: 'HS256', key: key)
        encoded_token.verify_claims!(time_policy: policy)
        expect(encoded_token.payload).to include('iat' => 100)
      end
    end
  end

  describe 'invalid signature' do
    let(:key) { 'secret' }
    let(:payload) { { 'jti' => 'id', 'iat' => 100, 'exp' => 200 } }
    let(:token) { JWT.encode(payload, key, 'HS256') }
    let(:jti_callback) { ->(*) { @jti_called = true } }
    let(:tracking_clock) do
      lambda {
        @clock_called = true
        110
      }
    end

    it 'does not trigger custom verification callbacks via JWT.decode' do
      expect do
        JWT.decode(token, 'wrong', true,
                   algorithm: 'HS256',
                   verify_jti: jti_callback,
                   verify_time_policy: { clock: tracking_clock })
      end.to raise_error(JWT::VerificationError)

      expect(@jti_called).to be_nil
      expect(@clock_called).to be_nil
    end

    it 'does not trigger custom verification callbacks via EncodedToken' do
      encoded_token = JWT::EncodedToken.new(token)

      expect do
        encoded_token.verify!(signature: { algorithm: 'HS256', key: 'wrong' },
                              claims: [{ jti: jti_callback }, { time_policy: { clock: tracking_clock } }])
      end.to raise_error(JWT::VerificationError)

      expect(@jti_called).to be_nil
      expect(@clock_called).to be_nil
    end
  end
end
