# frozen_string_literal: true

RSpec.describe JWT::EncodedToken::VerifyResult do
  let(:payload) do
    {
      'pay' => 'load',
      'nested' => { 'list' => %w[a b], 'deep' => { 'value' => 'x' } },
      'exp' => Time.now.to_i + 60,
      'iss' => 'issuer'
    }
  end
  let(:encoded_token) { JWT::Token.new(payload: payload).tap { |t| t.sign!(algorithm: 'HS256', key: 'secret') }.jwt }

  subject(:token) { JWT::EncodedToken.new(encoded_token) }

  describe '#verify_result' do
    subject(:result) { token.verify_result(signature: { algorithm: 'HS256', key: 'secret' }, claims: [:exp]) }

    it 'returns a successful result' do
      expect(result.verified?).to be(true)
      expect(result.success?).to be(true)
      expect(result.failure?).to be(false)
      expect(result.error).to be_nil
    end

    it 'exposes the verified data' do
      expect(result.payload).to eq(payload)
      expect(result.header).to eq(token.header)
      expect(result.jwt).to eq(encoded_token)
      expect(result.signature).to eq(token.signature)
      expect(result.signing_input).to eq(token.signing_input)
      expect(result.algorithm).to eq('HS256')
      expect(result.verified_at).to be_a(Time)
    end

    it 'binds the digest to the actual verified signature bytes' do
      expect(result.signature_digest).to eq(Digest::SHA256.hexdigest(token.signature))
    end

    it 'accepts signature options as top-level keyword arguments' do
      expect(token.verify_result(algorithm: 'HS256', key: 'secret').verified?).to be(true)
    end

    it 'allows accessing the payload via the token after verification' do
      result
      expect(token.payload).to eq(payload)
    end

    context 'when neither key nor key_finder is provided' do
      it 'raises ArgumentError' do
        expect { token.verify_result(signature: { algorithm: 'HS256' }) }.to raise_error(ArgumentError)
      end
    end

    describe 'immutability' do
      it 'freezes the result itself' do
        expect(result).to be_frozen
      end

      it 'prevents modification of the payload' do
        expect { result.payload['pay'] = 'changed' }.to raise_error(FrozenError)
      end

      it 'prevents modification of nested hashes' do
        expect { result.payload['nested']['deep']['value'] = 'changed' }.to raise_error(FrozenError)
      end

      it 'prevents modification of nested arrays' do
        expect { result.payload['nested']['list'] << 'c' }.to raise_error(FrozenError)
      end

      it 'prevents modification of nested strings' do
        expect { result.payload['pay'] << 'changed' }.to raise_error(FrozenError)
      end

      it 'prevents modification of the header' do
        expect { result.header['alg'] = 'none' }.to raise_error(FrozenError)
        expect { result.header['alg'].downcase! }.to raise_error(FrozenError)
      end

      it 'prevents modification of the signature bytes' do
        expect { result.signature << 'x' }.to raise_error(FrozenError)
      end

      it 'prevents modification of the verified claims list' do
        expect { result.verified_claims << :iss }.to raise_error(FrozenError)
      end

      it 'prevents modification of the token string' do
        expect { result.jwt << 'x' }.to raise_error(FrozenError)
      end

      it 'is not affected by in-place modification of the original token string' do
        original_jwt = result.jwt
        encoded_token.replace('garbage')

        expect(result.jwt).to eq(original_jwt)
      end

      it 'is not affected by later changes to the token payload' do
        result
        token.encoded_payload = JWT::Base64.url_encode(JWT::JSON.generate('pay' => 'tampered'))

        expect(result.payload['pay']).to eq('load')
      end

      it 'is not affected by later verifications with another key' do
        result
        token.verify_result(signature: { algorithm: 'HS256', key: 'other_secret' })

        expect(result.verified?).to be(true)
        expect(result.payload['pay']).to eq('load')
        expect(result.signature_digest).to eq(Digest::SHA256.hexdigest(token.signature))
      end
    end

    describe 'verified claims tracking' do
      it 'marks the requested claims as verified' do
        expect(result.verified_claims).to eq([:exp])
        expect(result.claim_verified?(:exp)).to be(true)
        expect(result.claim_verified?('exp')).to be(true)
      end

      it 'does not mark unchecked claims as verified' do
        expect(result.claim_verified?(:iss)).to be(false)
        expect(result.claim_verified?(:aud)).to be(false)
      end

      it 'verifies the exp claim by default' do
        default_result = token.verify_result(signature: { algorithm: 'HS256', key: 'secret' })

        expect(default_result.verified?).to be(true)
        expect(default_result.verified_claims).to eq([:exp])
      end

      context 'when claims are given as a Hash' do
        subject(:result) { token.verify_result(signature: { algorithm: 'HS256', key: 'secret' }, claims: { iss: 'issuer' }) }

        it 'marks the hash keys as verified claims' do
          expect(result.verified?).to be(true)
          expect(result.verified_claims).to eq([:iss])
          expect(result.claim_verified?(:iss)).to be(true)
          expect(result.claim_verified?(:exp)).to be(false)
        end
      end
    end

    describe 'failure handling' do
      context 'when the signature is invalid' do
        subject(:failure) { token.verify_result(signature: { algorithm: 'HS256', key: 'wrong_secret' }) }

        it 'returns a failed result' do
          expect(failure.verified?).to be(false)
          expect(failure.success?).to be(false)
          expect(failure.failure?).to be(true)
          expect(failure.error).to be_a(JWT::VerificationError)
        end

        it 'exposes no verified data' do
          expect(failure.payload).to be_nil
          expect(failure.header).to be_nil
          expect(failure.signature).to be_nil
          expect(failure.signature_digest).to be_nil
          expect(failure.algorithm).to be_nil
          expect(failure.verified_claims).to eq([])
          expect(failure.claim_verified?(:exp)).to be(false)
        end
      end

      context 'when the claims are invalid' do
        subject(:failure) { token.verify_result(signature: { algorithm: 'HS256', key: 'secret' }, claims: { iss: 'other' }) }

        it 'returns a failed result' do
          expect(failure.verified?).to be(false)
          expect(failure.error).to be_a(JWT::InvalidIssuerError)
        end
      end

      it 'does not reuse a previous successful result object' do
        success = token.verify_result(signature: { algorithm: 'HS256', key: 'secret' })
        failure = token.verify_result(signature: { algorithm: 'HS256', key: 'wrong_secret' })

        expect(failure).not_to be(success)
        expect(failure.verified?).to be(false)
        expect(success.verified?).to be(true)
      end

      it 'returns a new result object on every call' do
        first = token.verify_result(signature: { algorithm: 'HS256', key: 'secret' })
        second = token.verify_result(signature: { algorithm: 'HS256', key: 'secret' })

        expect(first).not_to be(second)
      end
    end

    context 'when payload is detached' do
      let(:signed_token) do
        JWT::Token.new(payload: payload).tap do |t|
          t.detach_payload!
          t.sign!(algorithm: 'HS256', key: 'secret')
        end
      end
      let(:encoded_token) { signed_token.jwt }

      before { token.encoded_payload = signed_token.encoded_payload }

      it 'returns a successful result' do
        expect(result.verified?).to be(true)
        expect(result.payload).to eq(payload)
      end

      context 'when the detached payload is replaced after verification' do
        it 'does not affect the returned result' do
          result
          token.encoded_payload = JWT::Base64.url_encode(JWT::JSON.generate('pay' => 'tampered'))

          expect(result.payload['pay']).to eq('load')
          expect(result.signature_digest).to eq(Digest::SHA256.hexdigest(signed_token.signature))
        end
      end
    end

    describe 'existing mutable APIs' do
      before { result }

      it 'continues to return mutable data' do
        expect(token.payload).not_to be_frozen
        expect(token.header).not_to be_frozen
        expect(token.unverified_payload).not_to be_frozen
        expect { token.payload['pay'] = 'changed' }.not_to raise_error
      end
    end
  end
end
