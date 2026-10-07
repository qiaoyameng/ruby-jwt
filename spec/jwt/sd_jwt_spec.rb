# frozen_string_literal: true

RSpec.describe JWT::SDJWT do
  let(:key) { 'secret' }

  def disclosure(*elements)
    JWT::Base64.url_encode(JWT::JSON.generate(elements))
  end

  def digest_of(disclosure_string)
    JWT::Base64.url_encode(Digest::SHA256.digest(disclosure_string))
  end

  def sd_jwt(payload, disclosures, jwt_key: key)
    token = JWT.encode(payload, jwt_key, 'HS256')
    "#{([token] + disclosures).join('~')}~"
  end

  let(:street_disclosure) { disclosure('salt-street', 'street_address', 'Schulstr. 12') }
  let(:country_disclosure) { disclosure('salt-country', 'country', 'DE') }
  let(:locality_disclosure) { disclosure('salt-locality', 'locality', 'Berlin') }
  let(:decoy_digest) { digest_of(disclosure('decoy-salt', 'decoy', 'decoy')) }

  let(:payload) do
    {
      'iss' => 'https://issuer.example',
      'address' => {
        '_sd' => [digest_of(street_disclosure), digest_of(country_disclosure), decoy_digest]
      },
      '_sd_alg' => 'sha-256'
    }
  end

  describe '.verify' do
    context 'with nested disclosures and a decoy digest' do
      subject(:result) do
        described_class.verify(sd_jwt(payload, [street_disclosure, country_disclosure]), key, true, algorithm: 'HS256')
      end

      it 'verifies the issuer signature and rebuilds the nested members' do
        expect(result.payload).to eq(
          'iss' => 'https://issuer.example',
          'address' => { 'street_address' => 'Schulstr. 12', 'country' => 'DE' }
        )
      end

      it 'exposes only the plaintext claims as plaintext' do
        expect(result.plaintext).to eq('iss' => 'https://issuer.example', 'address' => {})
      end

      it 'reports the disclosed positions' do
        expect(result.disclosed).to contain_exactly(
          [%w[address street_address], 'Schulstr. 12'],
          [%w[address country], 'DE']
        )
      end

      it 'reports the decoy digest as still hidden' do
        expect(result.hidden).to eq([[['address'], decoy_digest]])
      end
    end

    context 'when disclosures are given in a different order' do
      it 'produces the same result' do
        result = described_class.verify(sd_jwt(payload, [country_disclosure, street_disclosure]), key, true, algorithm: 'HS256')
        expect(result.payload['address']).to eq('street_address' => 'Schulstr. 12', 'country' => 'DE')
      end
    end

    context 'when a disclosure is withheld' do
      subject(:result) { described_class.verify(sd_jwt(payload, [street_disclosure]), key, true, algorithm: 'HS256') }

      it 'keeps the claim hidden instead of guessing a value' do
        expect(result.payload['address']).to eq('street_address' => 'Schulstr. 12')
        expect(result.payload['address']).not_to have_key('country')
        expect(result.hidden).to include([['address'], digest_of(country_disclosure)])
      end
    end

    context 'when a disclosed value is explicitly null' do
      let(:null_disclosure) { disclosure('salt-null', 'middle_name', nil) }
      let(:payload) { { '_sd' => [digest_of(null_disclosure)], '_sd_alg' => 'sha-256' } }

      it 'uses the disclosed null value' do
        result = described_class.verify(sd_jwt(payload, [null_disclosure]), key, true, algorithm: 'HS256')
        expect(result.payload).to eq('middle_name' => nil)
      end
    end

    context 'with a disclosure nested inside another disclosed value' do
      let(:inner_disclosure) { disclosure('salt-inner', 'city', 'Berlin') }
      let(:outer_disclosure) { disclosure('salt-outer', 'address', 'meta' => { '_sd' => [digest_of(inner_disclosure)] }) }
      let(:payload) { { '_sd' => [digest_of(outer_disclosure)], '_sd_alg' => 'sha-256' } }

      it 'resolves the nested digest' do
        result = described_class.verify(sd_jwt(payload, [outer_disclosure, inner_disclosure]), key, true, algorithm: 'HS256')
        expect(result.payload).to eq('address' => { 'meta' => { 'city' => 'Berlin' } })
      end
    end

    context 'with selectively disclosable array elements' do
      let(:element_disclosure) { disclosure('salt-element', 'US') }
      let(:payload) do
        {
          'nationalities' => ['DE', { '...' => digest_of(element_disclosure) }, { '...' => decoy_digest }],
          '_sd_alg' => 'sha-256'
        }
      end

      subject(:result) { described_class.verify(sd_jwt(payload, [element_disclosure]), key, true, algorithm: 'HS256') }

      it 'rebuilds the array element and drops the hidden placeholder' do
        expect(result.payload['nationalities']).to eq(%w[DE US])
        expect(result.plaintext['nationalities']).to eq(['DE'])
        expect(result.disclosed).to eq([[['nationalities', 1], 'US']])
        expect(result.hidden).to eq([[['nationalities', 2], decoy_digest]])
      end
    end

    context 'when the issuer signature is invalid' do
      it 'raises a verification error before processing disclosures' do
        token = sd_jwt(payload, [street_disclosure, country_disclosure])
        expect { described_class.verify(token, 'wrong-key', true, algorithm: 'HS256') }
          .to raise_error(JWT::VerificationError)
      end
    end

    context 'when the caller requires a different algorithm' do
      it 'raises an algorithm error' do
        token = sd_jwt(payload, [street_disclosure, country_disclosure])
        expect { described_class.verify(token, key, true, algorithm: 'RS256') }
          .to raise_error(JWT::IncorrectAlgorithm)
      end
    end

    context 'when the disclosure content is tampered with' do
      let(:tampered) { disclosure('salt-street', 'street_address', 'Forged 1') }

      it 'fails because the digest no longer matches' do
        token = sd_jwt(payload, [tampered, country_disclosure])
        expect { described_class.verify(token, key, true, algorithm: 'HS256') }
          .to raise_error(JWT::OrphanDisclosureError)
      end
    end

    context 'when the same disclosure is provided twice' do
      it 'raises a duplicate disclosure error' do
        token = sd_jwt(payload, [street_disclosure, street_disclosure, country_disclosure])
        expect { described_class.verify(token, key, true, algorithm: 'HS256') }
          .to raise_error(JWT::DuplicateDisclosureError)
      end
    end

    context 'when a disclosure digest is not referenced by the issuer JWT' do
      it 'raises an orphan disclosure error' do
        token = sd_jwt(payload, [street_disclosure, country_disclosure, locality_disclosure])
        expect { described_class.verify(token, key, true, algorithm: 'HS256') }
          .to raise_error(JWT::OrphanDisclosureError)
      end
    end

    context 'when a disclosed claim would override a plaintext claim' do
      let(:colliding) { disclosure('salt-iss', 'iss', 'https://evil.example') }
      let(:payload) { { 'iss' => 'https://issuer.example', '_sd' => [digest_of(colliding)], '_sd_alg' => 'sha-256' } }

      it 'raises a claim collision error' do
        token = sd_jwt(payload, [colliding])
        expect { described_class.verify(token, key, true, algorithm: 'HS256') }
          .to raise_error(JWT::ClaimCollisionError)
      end
    end

    context 'when a disclosure uses a reserved claim name' do
      let(:reserved) { disclosure('salt-sd', '_sd', 'value') }
      let(:payload) { { '_sd' => [digest_of(reserved)], '_sd_alg' => 'sha-256' } }

      it 'raises a reserved claim error' do
        token = sd_jwt(payload, [reserved])
        expect { described_class.verify(token, key, true, algorithm: 'HS256') }
          .to raise_error(JWT::ReservedClaimError)
      end
    end

    context 'when the payload uses "..." as an object member' do
      let(:payload) { { '...' => digest_of(street_disclosure), '_sd_alg' => 'sha-256' } }

      it 'raises a reserved claim error' do
        token = sd_jwt(payload, [street_disclosure])
        expect { described_class.verify(token, key, true, algorithm: 'HS256') }
          .to raise_error(JWT::ReservedClaimError)
      end
    end

    context 'when the digest algorithm is unknown' do
      let(:payload) { { 'iss' => 'https://issuer.example', '_sd_alg' => 'sha-512' } }

      it 'raises an unsupported algorithm error' do
        token = sd_jwt(payload, [])
        expect { described_class.verify(token, key, true, algorithm: 'HS256') }
          .to raise_error(JWT::UnsupportedSdAlgorithmError, /sha-512/)
      end
    end

    context 'when the SD-JWT carries a key-binding JWT' do
      it 'rejects the input' do
        kb_jwt = JWT.encode({ 'nonce' => 'abc' }, key, 'HS256')
        token = sd_jwt(payload, [street_disclosure, country_disclosure]) + kb_jwt
        expect { described_class.verify(token, key, true, algorithm: 'HS256') }
          .to raise_error(JWT::KeyBindingNotSupportedError)
      end
    end

    context 'when an array element disclosure is matched to an object digest' do
      let(:element_disclosure) { disclosure('salt-element', 'US') }
      let(:payload) { { '_sd' => [digest_of(element_disclosure)], '_sd_alg' => 'sha-256' } }

      it 'raises a malformed disclosure error' do
        token = sd_jwt(payload, [element_disclosure])
        expect { described_class.verify(token, key, true, algorithm: 'HS256') }
          .to raise_error(JWT::MalformedDisclosureError)
      end
    end

    context 'when a disclosure is not valid base64url encoded JSON' do
      it 'raises a malformed disclosure error' do
        token = sd_jwt(payload, [street_disclosure, country_disclosure, 'not-valid!!!'])
        expect { described_class.verify(token, key, true, algorithm: 'HS256') }
          .to raise_error(JWT::MalformedDisclosureError)
      end
    end

    context 'when the same digest is referenced twice by the issuer JWT' do
      let(:payload) { { '_sd' => [digest_of(street_disclosure), digest_of(street_disclosure)], '_sd_alg' => 'sha-256' } }

      it 'raises a duplicate disclosure error' do
        token = sd_jwt(payload, [street_disclosure])
        expect { described_class.verify(token, key, true, algorithm: 'HS256') }
          .to raise_error(JWT::DuplicateDisclosureError)
      end
    end

    context 'without a tilde separator' do
      it 'raises a malformed token error' do
        expect { described_class.verify(JWT.encode(payload, key, 'HS256'), key) }
          .to raise_error(JWT::MalformedTokenError)
      end
    end
  end
end
