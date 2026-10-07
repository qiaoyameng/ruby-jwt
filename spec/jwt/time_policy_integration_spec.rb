# frozen_string_literal: true

RSpec.describe 'JWT time policy integration' do
  def policy(clock = SpecSupport::AdvancingClock.new(100))
    JWT::Claims::TimePolicy.new(
      required_claims: %w[iat nbf exp],
      max_issued_age: 0,
      max_lifetime: 1,
      clock: clock
    )
  end
  let(:payload) { { 'iat' => 100, 'nbf' => 100, 'exp' => 101, 'jti' => 'token-id' } }
  let(:token) { JWT.encode(payload, 'secret', 'HS256') }

  it 'accepts a boundary-valid token through both entry points with one clock read' do
    expect(JWT.decode(token, 'secret', true, algorithm: 'HS256', time_policy: policy)).to eq([payload, { 'alg' => 'HS256' }])

    encoded_token = JWT::EncodedToken.new(token)
    expect(encoded_token.verify!(signature: { algorithm: 'HS256', key: 'secret' }, claims: policy)).to be_nil
    expect(encoded_token.payload).to eq(payload)
  end

  it 'returns the same relationship error through both entry points' do
    invalid_payload = payload.merge('iat' => 201)
    invalid_token = JWT.encode(invalid_payload, 'secret', 'HS256')
    relationship_policy = JWT::Claims::TimePolicy.new(clock: -> { 100 })

    expect { JWT.decode(invalid_token, 'secret', true, algorithm: 'HS256', time_policy: relationship_policy) }
      .to raise_error(JWT::InvalidPayload, 'iat must not be later than exp')

    encoded_token = JWT::EncodedToken.new(invalid_token)
    expect do
      encoded_token.verify!(signature: { algorithm: 'HS256', key: 'secret' },
                            claims: { time_policy: relationship_policy })
    end
      .to raise_error(JWT::InvalidPayload, 'iat must not be later than exp')
  end

  it 'does not invoke a business callback from JWT.decode when the signature is invalid' do
    callback_called = 0
    callback = ->(_jti) { callback_called += 1 }
    invalid_token = JWT.encode(payload, 'wrong', 'HS256')

    expect do
      JWT.decode(invalid_token, 'secret', true,
                 algorithm: 'HS256', time_policy: policy, verify_jti: callback)
    end.to raise_error(JWT::VerificationError, 'Signature verification failed')

    expect(callback_called).to eq(0)
  end

  it 'does not invoke a business callback from EncodedToken when the signature is invalid' do
    callback_called = 0
    callback = ->(_jti) { callback_called += 1 }
    invalid_token = JWT.encode(payload, 'wrong', 'HS256')
    encoded_token = JWT::EncodedToken.new(invalid_token)

    expect do
      encoded_token.verify!(signature: { algorithm: 'HS256', key: 'secret' },
                            claims: { time_policy: policy, jti: callback })
    end.to raise_error(JWT::VerificationError, 'Signature verification failed')

    expect(callback_called).to eq(0)
  end
end
