# frozen_string_literal: true

RSpec.describe JWT::SDJWT do
  let(:secret) { 'issuer-secret' }
  let(:algorithm) { 'HS256' }

  def disclosure_for(*elements)
    JWT::Base64.url_encode(JWT::JSON.generate(elements))
  end

  def digest_of(disclosure)
    JWT::Base64.url_encode(Digest::SHA256.digest(disclosure))
  end

  def issue(payload)
    JWT.encode(payload, secret, algorithm)
  end

  def verify(jwt, disclosures = [], key: secret)
    described_class.verify(jwt, disclosures, key, algorithm: algorithm)
  end

  describe '.verify' do
    context 'when the issuer signature is invalid' do
      it 'raises a verification error' do
        jwt = issue('sub' => 'user-1')

        expect { verify(jwt, key: 'wrong-secret') }.to raise_error(JWT::VerificationError)
      end
    end

    context 'without any disclosures' do
      it 'returns the plaintext claims' do
        result = verify(issue('sub' => 'user-1'))

        expect(result.payload).to eq('sub' => 'user-1')
        expect(result.plaintext).to eq('sub' => 'user-1')
        expect(result.disclosed).to eq({})
        expect(result.hidden).to eq([])
      end
    end

    context 'with object member disclosures' do
      let(:given_name) { disclosure_for('salt-1', 'given_name', 'John') }
      let(:family_name) { disclosure_for('salt-2', 'family_name', 'Doe') }
      let(:payload) do
        { 'sub' => 'user-1', '_sd_alg' => 'sha-256', '_sd' => [digest_of(given_name), digest_of(family_name)] }
      end

      it 'reconstructs the disclosed claims' do
        result = verify(issue(payload), [given_name, family_name])

        expect(result.payload).to eq('sub' => 'user-1', 'given_name' => 'John', 'family_name' => 'Doe')
        expect(result.disclosed).to eq('given_name' => 'John', 'family_name' => 'Doe')
        expect(result.plaintext).to eq(payload)
        expect(result.hidden).to eq([])
      end

      it 'does not depend on the order of the disclosures' do
        result = verify(issue(payload), [family_name, given_name])

        expect(result.payload).to eq('sub' => 'user-1', 'given_name' => 'John', 'family_name' => 'Doe')
      end

      it 'computes digests over the raw encoded disclosure' do
        disclosure = JWT::Base64.url_encode('[ "salt-1", "given_name", "John" ]')
        jwt = issue('_sd' => [digest_of(disclosure)])

        expect(verify(jwt, [disclosure]).payload).to eq('given_name' => 'John')
      end

      it 'detects tampered disclosure content' do
        altered = JWT::Base64.url_encode("#{JWT::JSON.generate(%w[salt-1 given_name John])} ")

        expect { verify(issue(payload), [altered, family_name]) }.to raise_error(JWT::OrphanDisclosureError)
      end
    end

    context 'with array element disclosures' do
      let(:france) { disclosure_for('salt-1', 'FR') }
      let(:payload) { { 'nationalities' => ['DE', { '...' => digest_of(france) }] } }

      it 'reconstructs the disclosed array element' do
        result = verify(issue(payload), [france])

        expect(result.payload).to eq('nationalities' => %w[DE FR])
        expect(result.disclosed['nationalities'][1]).to eq('FR')
        expect(result.disclosed['nationalities'][0]).to be_a(JWT::SDJWT::HiddenValue)
      end

      context 'when the element stays concealed' do
        it 'marks the position as hidden without guessing a value' do
          result = verify(issue(payload))

          hidden = result.payload['nationalities'][1]
          expect(hidden).to eq(JWT::SDJWT::HiddenValue.new(path: ['nationalities', 1], digest: digest_of(france)))
          expect(result.hidden).to eq([hidden])
          expect(result.disclosed).to eq({})
        end
      end
    end

    context 'with nested disclosures' do
      let(:street) { disclosure_for('salt-1', 'street_address', 'Main Street 1') }
      let(:address) { disclosure_for('salt-2', 'address', 'country' => 'DE', '_sd' => [digest_of(street)]) }
      let(:payload) { { 'sub' => 'user-1', '_sd' => [digest_of(address)] } }

      it 'reconstructs the nested structure' do
        result = verify(issue(payload), [address, street])

        expect(result.payload).to eq('sub' => 'user-1', 'address' => { 'country' => 'DE', 'street_address' => 'Main Street 1' })
        expect(result.disclosed).to eq('address' => { 'country' => 'DE', 'street_address' => 'Main Street 1' })
      end

      it 'does not depend on the nesting order of the disclosures' do
        result = verify(issue(payload), [street, address])

        expect(result.payload).to eq('sub' => 'user-1', 'address' => { 'country' => 'DE', 'street_address' => 'Main Street 1' })
      end

      context 'when the inner disclosure is tampered with' do
        let(:tampered) { disclosure_for('salt-1', 'street_address', 'Forged Alley 9') }

        it 'fails instead of accepting the forged value' do
          expect { verify(issue(payload), [address, tampered]) }.to raise_error(JWT::OrphanDisclosureError)
        end
      end

      context 'when the inner disclosure is missing' do
        it 'keeps the nested member hidden' do
          result = verify(issue(payload), [address])

          expect(result.payload).to eq('sub' => 'user-1', 'address' => { 'country' => 'DE' })
          expect(result.payload['address']).not_to have_key('street_address')
          expect(result.hidden).to eq([JWT::SDJWT::HiddenValue.new(path: ['address'], digest: digest_of(street))])
        end
      end

      context 'when a disclosure is repeated' do
        it 'fails' do
          expect { verify(issue(payload), [address, street, street]) }.to raise_error(JWT::DuplicateDisclosureError)
        end
      end
    end

    context 'with undigested decoy digests' do
      let(:decoy) { digest_of(disclosure_for('salt-9', 'decoy', 'value')) }
      let(:payload) { { 'sub' => 'user-1', '_sd' => [decoy] } }

      it 'keeps the position hidden without fabricating a value' do
        result = verify(issue(payload))

        expect(result.payload).to eq('sub' => 'user-1')
        expect(result.payload).not_to have_key('decoy')
        expect(result.hidden).to eq([JWT::SDJWT::HiddenValue.new(path: [], digest: decoy)])
      end
    end

    context 'with an unsupported digest algorithm' do
      it 'rejects unknown algorithms' do
        jwt = issue('_sd_alg' => 'sha-512', '_sd' => [])

        expect { verify(jwt) }.to raise_error(JWT::UnsupportedDigestAlgorithm, /sha-512/)
      end

      it 'rejects non-string algorithms' do
        jwt = issue('_sd_alg' => 256)

        expect { verify(jwt) }.to raise_error(JWT::UnsupportedDigestAlgorithm)
      end
    end

    context 'with malformed disclosures' do
      let(:payload) { { '_sd' => ['digest'] } }

      it 'rejects invalid base64url' do
        expect { verify(issue(payload), ['!!!']) }.to raise_error(JWT::MalformedDisclosureError)
      end

      it 'rejects non-JSON content' do
        expect { verify(issue(payload), [JWT::Base64.url_encode('not json')]) }.to raise_error(JWT::MalformedDisclosureError)
      end

      it 'rejects non-array content' do
        expect { verify(issue(payload), [JWT::Base64.url_encode('{"a":1}')]) }.to raise_error(JWT::MalformedDisclosureError)
      end

      it 'rejects arrays with too many elements' do
        expect { verify(issue(payload), [disclosure_for('s', 'a', 'b', 'c')]) }.to raise_error(JWT::MalformedDisclosureError)
      end

      it 'rejects a non-string salt' do
        expect { verify(issue(payload), [disclosure_for(1, 'a', 'b')]) }.to raise_error(JWT::MalformedDisclosureError)
      end

      it 'rejects a non-string claim name' do
        expect { verify(issue(payload), [disclosure_for('s', 1, 'b')]) }.to raise_error(JWT::MalformedDisclosureError)
      end

      it 'rejects non-string disclosures' do
        expect { verify(issue(payload), [nil]) }.to raise_error(JWT::MalformedDisclosureError)
      end
    end

    context 'with disclosure misuse' do
      let(:disclosure) { disclosure_for('salt-1', 'given_name', 'John') }

      it 'rejects disclosures without a matching digest' do
        expect { verify(issue('sub' => 'user-1'), [disclosure]) }.to raise_error(JWT::OrphanDisclosureError)
      end

      it 'rejects disclosures overwriting a plaintext claim' do
        jwt = issue('given_name' => 'Jane', '_sd' => [digest_of(disclosure)])

        expect { verify(jwt, [disclosure]) }.to raise_error(JWT::DisclosedClaimConflictError)
      end

      it 'rejects disclosures overwriting another disclosed claim' do
        other = disclosure_for('salt-2', 'given_name', 'Jack')
        jwt = issue('_sd' => [digest_of(disclosure), digest_of(other)])

        expect { verify(jwt, [disclosure, other]) }.to raise_error(JWT::DisclosedClaimConflictError)
      end

      it 'rejects disclosures with reserved claim names' do
        %w[_sd _sd_alg ...].each do |reserved|
          reserved_disclosure = disclosure_for('salt-1', reserved, 'x')
          jwt = issue('_sd' => [digest_of(reserved_disclosure)])

          expect { verify(jwt, [reserved_disclosure]) }.to raise_error(JWT::DisclosedClaimConflictError)
        end
      end

      it 'rejects a disclosure consumed more than once' do
        jwt = issue('_sd' => [digest_of(disclosure), digest_of(disclosure)])

        expect { verify(jwt, [disclosure]) }.to raise_error(JWT::DuplicateDisclosureError)
      end

      it 'rejects an object member disclosure used for an array placeholder' do
        jwt = issue('items' => [{ '...' => digest_of(disclosure) }])

        expect { verify(jwt, [disclosure]) }.to raise_error(JWT::MalformedDisclosureError)
      end

      it 'rejects an array element disclosure used for an object member' do
        element = disclosure_for('salt-1', 'FR')
        jwt = issue('_sd' => [digest_of(element)])

        expect { verify(jwt, [element]) }.to raise_error(JWT::MalformedDisclosureError)
      end
    end

    context 'with malformed SD-JWT structures' do
      it 'rejects a non-array _sd claim' do
        expect { verify(issue('_sd' => 'digest')) }.to raise_error(JWT::MalformedSDJWTError)
      end

      it 'rejects non-string digests in _sd' do
        expect { verify(issue('_sd' => [1])) }.to raise_error(JWT::MalformedSDJWTError)
      end

      it 'rejects array placeholders with extra keys' do
        expect { verify(issue('items' => [{ '...' => 'digest', 'extra' => 1 }])) }.to raise_error(JWT::MalformedSDJWTError)
      end

      it 'rejects non-string array placeholder digests' do
        expect { verify(issue('items' => [{ '...' => 1 }])) }.to raise_error(JWT::MalformedSDJWTError)
      end
    end

    it 'exposes the issuer JWT header' do
      result = verify(issue('sub' => 'user-1'))

      expect(result.header).to include('alg' => algorithm)
    end
  end

  describe '.verify_presentation' do
    let(:given_name) { disclosure_for('salt-1', 'given_name', 'John') }
    let(:jwt) { issue('sub' => 'user-1', '_sd' => [digest_of(given_name)]) }

    it 'verifies a presentation with disclosures' do
      result = described_class.verify_presentation("#{jwt}~#{given_name}~", secret, algorithm: algorithm)

      expect(result.payload).to eq('sub' => 'user-1', 'given_name' => 'John')
    end

    it 'verifies a presentation without disclosures' do
      result = described_class.verify_presentation("#{jwt}~", secret, algorithm: algorithm)

      expect(result.payload).to eq('sub' => 'user-1')
      expect(result.hidden.size).to eq(1)
    end

    it 'rejects presentations carrying a key binding JWT' do
      kb_jwt = JWT.encode({ 'aud' => 'verifier' }, 'holder-secret', 'HS256')

      expect do
        described_class.verify_presentation("#{jwt}~#{given_name}~#{kb_jwt}", secret, algorithm: algorithm)
      end.to raise_error(JWT::KeyBindingNotSupportedError)
    end

    it 'rejects empty presentations' do
      expect { described_class.verify_presentation('', secret, algorithm: algorithm) }.to raise_error(JWT::MalformedSDJWTError)
    end
  end
end
