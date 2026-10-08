# frozen_string_literal: true

RSpec.describe JWT::VerifyResult do
  let(:payload) { { 'pay' => 'load', 'nested' => { 'list' => %w[a b], 'deep' => { 'x' => 'y' } } } }
  let(:encoded_token) { JWT::Token.new(payload: payload).tap { |t| t.sign!(algorithm: 'HS256', key: 'secret') }.jwt }
  let(:token) { JWT::EncodedToken.new(encoded_token) }

  subject(:result) { token.verify_result(signature: { algorithm: 'HS256', key: 'secret' }) }

  it 'returns a VerifyResult' do
    expect(result).to be_a(described_class)
  end

  it 'exposes the verified payload and header' do
    expect(result.payload).to eq(payload)
    expect(result.header).to eq({ 'alg' => 'HS256' })
  end

  it 'records the verification time' do
    expect(result.verified_at).to be_within(5).of(Time.now)
  end

  it 'is frozen itself' do
    expect(result).to be_frozen
  end

  it 'reports itself as verified' do
    expect(result.verified?).to be(true)
  end

  describe 'immutability' do
    it 'freezes the header and payload' do
      expect { result.header['alg'] = 'none' }.to raise_error(FrozenError)
      expect { result.payload['pay'] = 'tampered' }.to raise_error(FrozenError)
    end

    it 'freezes nested hashes, arrays and strings' do
      expect { result.payload['nested']['deep']['x'] = 'z' }.to raise_error(FrozenError)
      expect { result.payload['nested']['list'] << 'c' }.to raise_error(FrozenError)
      expect { result.payload['nested']['list'][0] << 'x' }.to raise_error(FrozenError)
      expect { result.payload['pay'] << 'x' }.to raise_error(FrozenError)
    end

    it 'freezes the signature, signing input and jwt' do
      expect { result.signature << 'x' }.to raise_error(FrozenError)
      expect { result.signing_input << 'x' }.to raise_error(FrozenError)
      expect { result.jwt << 'x' }.to raise_error(FrozenError)
    end

    it 'does not freeze the data returned by the token itself' do
      result
      token.payload['pay'] = 'changed'
      expect(token.payload['pay']).to eq('changed')
      expect(result.payload['pay']).to eq('load')
    end

    it 'is not affected by in-place mutation of the original token string' do
      result
      encoded_token.replace('tampered.token.string')
      expect(result.jwt).not_to eq('tampered.token.string')
      expect(result.jwt).to include('.')
    end
  end

  describe 'signature binding' do
    it 'exposes the verified signature bytes' do
      expect(result.signature).to eq(token.signature)
    end

    it 'exposes a digest of the actual verified signature bytes' do
      expect(result.signature_digest).to eq(Digest::SHA256.hexdigest(token.signature))
    end

    it 'exposes the signing input that was verified' do
      expect(result.signing_input).to eq(token.signing_input)
    end
  end

  describe 'verification policy' do
    it 'records the signature algorithm' do
      expect(result.signature_algorithm).to eq('HS256')
    end

    it 'verifies the exp claim by default' do
      expect(result.verified_claims).to eq([:exp])
      expect(result.claim_verified?(:exp)).to be(true)
    end

    it 'does not report claims that were not verified as verified' do
      expect(result.claim_verified?(:nbf)).to be(false)
      expect(result.claim_verified?(:iss)).to be(false)
      expect(result.claim_verified?('iat')).to be(false)
    end

    context 'when specific claims are verified' do
      subject(:result) { token.verify_result(signature: { algorithm: 'HS256', key: 'secret' }, claims: %i[exp iat]) }

      it 'records exactly those claims' do
        expect(result.verified_claims).to contain_exactly(:exp, :iat)
        expect(result.claim_verified?(:iat)).to be(true)
        expect(result.claim_verified?(:nbf)).to be(false)
      end
    end

    context 'when claims are given as a hash' do
      subject(:result) { token.verify_result(signature: { algorithm: 'HS256', key: 'secret' }, claims: { exp: { leeway: 10 } }) }

      it 'records the claims from the hash keys' do
        expect(result.verified_claims).to eq([:exp])
        expect(result.claim_verified?(:exp)).to be(true)
      end
    end
  end

  describe 'isolation from the token after verification' do
    let(:other_payload) { { 'pay' => 'other' } }
    let(:other_token) { JWT::Token.new(payload: other_payload).tap { |t| t.sign!(algorithm: 'HS256', key: 'secret') } }

    it 'is not affected by swapping the detached payload afterwards' do
      result
      token.encoded_payload = other_token.encoded_payload
      expect { token.verify!(signature: { algorithm: 'HS256', key: 'secret' }) }.to raise_error(JWT::VerificationError)

      expect(result.payload).to eq(payload)
      expect(result.signature_digest).to eq(Digest::SHA256.hexdigest(JWT::Base64.url_decode(encoded_token.split('.').last)))
    end

    it 'is not affected by verifying the token with another key afterwards' do
      result
      expect { token.verify_signature!(algorithm: 'HS256', key: 'other-secret') }.to raise_error(JWT::VerificationError)

      expect(result.payload).to eq(payload)
      expect(result.signature).to eq(JWT::Base64.url_decode(encoded_token.split('.').last))
    end

    it 'returns a new object on each call' do
      expect(token.verify_result(signature: { algorithm: 'HS256', key: 'secret' })).not_to be(result)
    end
  end

  describe 'failed verification' do
    it 'raises on invalid signature and does not reuse a previous result' do
      first = result
      expect { token.verify_result(signature: { algorithm: 'HS256', key: 'wrong' }) }.to raise_error(JWT::VerificationError)
      expect(first.payload).to eq(payload)
    end

    it 'raises on invalid claims' do
      expired = JWT::Token.new(payload: { 'exp' => Time.now.to_i - 100 }).tap { |t| t.sign!(algorithm: 'HS256', key: 'secret') }.jwt
      expired_token = JWT::EncodedToken.new(expired)

      expect { expired_token.verify_result(signature: { algorithm: 'HS256', key: 'secret' }) }.to raise_error(JWT::ClaimValidationError)
    end
  end

  describe 'existing mutable APIs' do
    it 'keeps returning mutable data from the token' do
      token.verify!(signature: { algorithm: 'HS256', key: 'secret' })

      expect(token.payload).not_to be_frozen
      expect(token.header).not_to be_frozen
      expect(token.unverified_payload).not_to be_frozen
    end
  end
end
