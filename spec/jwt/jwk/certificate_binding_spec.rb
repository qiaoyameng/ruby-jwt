# frozen_string_literal: true

RSpec.describe JWT::JWK::CertificateBinding do
  let(:root_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:root_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake-ca/CN=Fake CA') }
  let(:root_certificate) { generate_root_cert(root_dn, root_key) }

  let(:leaf_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:leaf_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake/CN=Fake') }
  let(:leaf_serial) { 2 }
  let(:leaf_not_after) { Time.now + 3600 }
  let(:leaf_certificate) do
    generate_cert(leaf_dn, leaf_key, leaf_serial, issuer_cert: root_certificate, issuer_key: root_key, not_after: leaf_not_after)
  end

  let(:x5c) { [Base64.strict_encode64(leaf_certificate.to_der)] }
  let(:jwk_params) { JWT::JWK::RSA.new(leaf_key).export.merge(x5c: x5c) }
  let(:certificate_binding_options) { { root_certificates: [root_certificate] } }
  let(:options) { { certificate_binding: certificate_binding_options } }

  subject(:imported_jwk) { JWT::JWK.import(jwk_params, nil, options) }

  it 'imports a JWK bound to a valid certificate chain' do
    expect(imported_jwk).to be_a(JWT::JWK::RSA)
    expect(imported_jwk[:x5c]).to eq(x5c)
  end

  it 'produces a key that verifies tokens signed by the certified key' do
    token = JWT.encode({ 'data' => 'something' }, leaf_key, 'RS256')
    payload, = JWT.decode(token, imported_jwk.verify_key, true, algorithms: ['RS256'])
    expect(payload).to eq('data' => 'something')
  end

  context 'with x5t and x5t#S256 thumbprints' do
    let(:jwk_params) do
      super().merge(
        x5t: thumbprint(leaf_certificate, OpenSSL::Digest::SHA1),
        'x5t#S256': thumbprint(leaf_certificate, OpenSSL::Digest::SHA256)
      )
    end

    it 'imports the JWK when both thumbprints match the leaf certificate' do
      expect(imported_jwk[:x5t]).to eq(jwk_params[:x5t])
      expect(imported_jwk[:'x5t#S256']).to eq(jwk_params[:'x5t#S256'])
    end

    context 'when x5t is not valid base64url' do
      let(:jwk_params) { super().merge(x5t: '!!!not-base64!!!') }

      it 'raises a thumbprint error' do
        expect { imported_jwk }.to raise_error(JWT::CertificateThumbprintError, 'The x5t parameter is not valid base64url')
      end
    end

    context 'when x5t decodes to an unexpected length' do
      let(:jwk_params) { super().merge(x5t: JWT::Base64.url_encode('too-short')) }

      it 'raises a thumbprint error' do
        expect { imported_jwk }.to raise_error(JWT::CertificateThumbprintError, /invalid encoding/)
      end
    end

    context 'when x5t#S256 does not match the leaf certificate' do
      let(:jwk_params) { super().merge('x5t#S256': thumbprint(root_certificate, OpenSSL::Digest::SHA256)) }

      it 'raises a thumbprint error' do
        expect { imported_jwk }.to raise_error(JWT::CertificateThumbprintError, 'The x5t#S256 parameter does not match the digest of the leaf certificate')
      end
    end
  end

  context 'with an intermediate certificate' do
    let(:intermediate_key) { OpenSSL::PKey::RSA.generate(2048) }
    let(:intermediate_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake-ca/CN=Fake Intermediate CA') }
    let(:intermediate_certificate) do
      generate_cert(intermediate_dn, intermediate_key, 3, issuer_cert: root_certificate, issuer_key: root_key, certificate_authority: true)
    end
    let(:leaf_certificate) do
      generate_cert(leaf_dn, leaf_key, leaf_serial, issuer_cert: intermediate_certificate, issuer_key: intermediate_key)
    end
    let(:x5c) { [leaf_certificate, intermediate_certificate].map { |cert| Base64.strict_encode64(cert.to_der) } }

    it 'imports the JWK when the chain is in order' do
      expect(imported_jwk).to be_a(JWT::JWK::RSA)
    end

    context 'when the certificates are in the wrong order' do
      let(:x5c) { [intermediate_certificate, leaf_certificate].map { |cert| Base64.strict_encode64(cert.to_der) } }

      it 'raises a chain error' do
        expect { imported_jwk }.to raise_error(JWT::CertificateChainError, /not in order/)
      end
    end
  end

  context 'when the leaf certificate carries another valid public key' do
    let(:other_key) { OpenSSL::PKey::RSA.generate(2048) }
    let(:jwk_params) { JWT::JWK::RSA.new(other_key).export.merge(x5c: x5c) }

    it 'raises a key mismatch error' do
      expect { imported_jwk }.to raise_error(JWT::CertificateKeyMismatchError, /does not match the public key parameters/)
    end
  end

  context 'when the root certificate is only present in the x5c parameter' do
    let(:x5c) { [leaf_certificate, root_certificate].map { |cert| Base64.strict_encode64(cert.to_der) } }
    let(:certificate_binding_options) { { root_certificates: [] } }

    it 'does not trust the x5c provided root' do
      expect { imported_jwk }.to raise_error(JWT::CertificateChainError, /Certificate verification failed/)
    end
  end

  context 'when a certificate cannot be parsed' do
    let(:x5c) { [JWT::Base64.url_encode('not a certificate')] }

    it 'raises a chain error' do
      expect { imported_jwk }.to raise_error(JWT::CertificateChainError, /Unable to parse the x5c certificate chain/)
    end
  end

  context 'with a verification time' do
    let(:certificate_binding_options) { { root_certificates: [root_certificate], time: verification_time } }

    context 'within the validity period' do
      let(:verification_time) { Time.now }

      it 'imports the JWK' do
        expect(imported_jwk).to be_a(JWT::JWK::RSA)
      end
    end

    context 'after the leaf certificate has expired' do
      let(:verification_time) { leaf_not_after + 60 }

      it 'raises a chain error' do
        expect { imported_jwk }.to raise_error(JWT::CertificateChainError, /certificate has expired/)
      end
    end
  end

  context 'with allowed signature algorithms' do
    context 'covering the chain' do
      let(:certificate_binding_options) { { root_certificates: [root_certificate], allowed_algorithms: ['sha256WithRSAEncryption'] } }

      it 'imports the JWK' do
        expect(imported_jwk).to be_a(JWT::JWK::RSA)
      end
    end

    context 'not covering the chain' do
      let(:certificate_binding_options) { { root_certificates: [root_certificate], allowed_algorithms: ['sha512WithRSAEncryption'] } }

      it 'raises a chain error' do
        expect { imported_jwk }.to raise_error(JWT::CertificateChainError, /sha256WithRSAEncryption is not allowed/)
      end
    end
  end

  context 'with CRLs' do
    let(:certificate_binding_options) { { root_certificates: [root_certificate], crls: [crl] } }

    context 'when the leaf certificate is not revoked' do
      let(:crl) { issue_crl([], issuer: root_certificate, issuer_key: root_key) }

      it 'imports the JWK' do
        expect(imported_jwk).to be_a(JWT::JWK::RSA)
      end
    end

    context 'when the leaf certificate is revoked' do
      let(:crl) { issue_crl([[leaf_serial, Time.now - 60, 1]], issuer: root_certificate, issuer_key: root_key) }

      it 'raises a chain error' do
        expect { imported_jwk }.to raise_error(JWT::CertificateChainError, /certificate revoked/)
      end
    end
  end

  context 'with an EC key' do
    let(:root_key) { OpenSSL::PKey::EC.generate('prime256v1') }
    let(:leaf_key) { OpenSSL::PKey::EC.generate('prime256v1') }
    let(:jwk_params) { JWT::JWK::EC.new(leaf_key).export.merge(x5c: x5c) }
    let(:certificate_binding_options) { { root_certificates: [root_certificate], allowed_algorithms: ['ecdsa-with-SHA256'] } }

    it 'imports a JWK bound to a valid certificate chain' do
      expect(imported_jwk).to be_a(JWT::JWK::EC)
    end

    it 'produces a key that verifies tokens signed by the certified key' do
      token = JWT.encode({ 'data' => 'something' }, leaf_key, 'ES256')
      payload, = JWT.decode(token, imported_jwk.verify_key, true, algorithms: ['ES256'])
      expect(payload).to eq('data' => 'something')
    end

    context 'when the leaf certificate carries another valid public key' do
      let(:jwk_params) { JWT::JWK::EC.new(OpenSSL::PKey::EC.generate('prime256v1')).export.merge(x5c: x5c) }

      it 'raises a key mismatch error' do
        expect { imported_jwk }.to raise_error(JWT::CertificateKeyMismatchError, /does not match the public key parameters/)
      end
    end

    context 'when the certificate key type does not match the JWK key type' do
      let(:jwk_params) { JWT::JWK::RSA.new(OpenSSL::PKey::RSA.generate(2048)).export.merge(x5c: x5c) }

      it 'raises a key mismatch error' do
        expect { imported_jwk }.to raise_error(JWT::CertificateKeyMismatchError)
      end
    end
  end

  context 'without an x5c parameter' do
    let(:jwk_params) { JWT::JWK::RSA.new(leaf_key).export }

    it 'imports the JWK when binding options are given' do
      expect(imported_jwk).to be_a(JWT::JWK::RSA)
    end

    it 'imports the JWK without any options' do
      expect(JWT::JWK.import(jwk_params)).to be_a(JWT::JWK::RSA)
    end
  end

  context 'when the binding check fails' do
    let(:jwk_params) { JWT::JWK::RSA.new(OpenSSL::PKey::RSA.generate(2048)).export.merge(x5c: x5c) }

    it 'prevents the JWK from entering a key set usable for verification' do
      expect { JWT::JWK::Set.new([jwk_params], options) }.to raise_error(JWT::CertificateKeyMismatchError)
    end

    it 'prevents the JWK from being imported' do
      expect { imported_jwk }.to raise_error(JWT::CertificateKeyMismatchError)
    end
  end

  describe 'error hierarchy' do
    it 'provides distinguishable errors under JWT::JWKError' do
      expect(JWT::CertificateChainError).to be < JWT::CertificateBindingError
      expect(JWT::CertificateKeyMismatchError).to be < JWT::CertificateBindingError
      expect(JWT::CertificateThumbprintError).to be < JWT::CertificateBindingError
      expect(JWT::CertificateBindingError).to be < JWT::JWKError
    end
  end

  def thumbprint(certificate, digest)
    JWT::Base64.url_encode(digest.digest(certificate.to_der))
  end

  def generate_root_cert(root_dn, root_key)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = root_dn
    cert.issuer = root_dn
    cert.public_key = root_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 3600
    ef = OpenSSL::X509::ExtensionFactory.new
    cert.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.sign(root_key, 'sha256')
    cert
  end

  def generate_cert(subject_dn, key, serial, issuer_cert:, issuer_key:, certificate_authority: false, not_after: nil) # rubocop:disable Metrics/ParameterLists
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = subject_dn
    cert.issuer = issuer_cert.subject
    cert.public_key = key
    cert.not_before = Time.now - 3600
    cert.not_after = not_after || (Time.now + 3600)
    if certificate_authority
      ef = OpenSSL::X509::ExtensionFactory.new
      cert.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', true))
    end
    cert.sign(issuer_key, 'sha256')
    cert
  end

  def issue_crl(revocations, issuer:, issuer_key:)
    crl = OpenSSL::X509::CRL.new
    crl.issuer = issuer.subject
    crl.version = 1
    crl.last_update = Time.now - 3600
    crl.next_update = Time.now + 3600

    revocations.each do |rserial, time, reason_code|
      revoked = OpenSSL::X509::Revoked.new
      revoked.serial = rserial
      revoked.time = time
      revoked.add_extension(OpenSSL::X509::Extension.new('CRLReason', OpenSSL::ASN1::Enumerated(reason_code)))
      crl.add_revoked(revoked)
    end

    crl.add_extension(OpenSSL::X509::Extension.new('crlNumber', OpenSSL::ASN1::Integer(1)))
    crl.sign(issuer_key, 'sha256')
    crl
  end
end
