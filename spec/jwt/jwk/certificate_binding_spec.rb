# frozen_string_literal: true

RSpec.describe JWT::JWK::CertificateBinding do
  let(:root_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:root_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake-ca/CN=Fake Root CA') }
  let(:root_certificate) { generate_root_certificate(root_dn, root_key) }

  let(:intermediate_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:intermediate_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake-ca/CN=Fake Intermediate CA') }
  let(:intermediate_certificate) do
    cert = build_certificate(intermediate_dn, intermediate_key, 2, issuer: root_certificate)
    cert.add_extension(extension_factory.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.sign(root_key, 'sha256')
    cert
  end

  let(:leaf_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:leaf_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake/CN=Fake Leaf') }
  let(:leaf_certificate) do
    cert = build_certificate(leaf_dn, leaf_key, 3, issuer: intermediate_certificate)
    cert.sign(intermediate_key, 'sha256')
    cert
  end

  let(:x5c) { [leaf_certificate, intermediate_certificate].map { |cert| Base64.strict_encode64(cert.to_der) } }
  let(:x5t) { JWT::Base64.url_encode(OpenSSL::Digest::SHA1.digest(leaf_certificate.to_der)) }
  let(:x5t_s256) { JWT::Base64.url_encode(OpenSSL::Digest::SHA256.digest(leaf_certificate.to_der)) }

  let(:jwk_params) { JWT::JWK::RSA.new(leaf_key).export.merge(x5c: x5c, x5t: x5t, 'x5t#S256': x5t_s256) }
  let(:binding_options) { { x5c: { root_certificates: [root_certificate] } } }

  subject(:imported_jwk) { JWT::JWK.import(jwk_params, nil, binding_options) }

  context 'with a valid RSA JWK carrying x5c, x5t and x5t#S256' do
    it 'imports the JWK and binds it to the leaf certificate key' do
      expect(imported_jwk).to be_a(JWT::JWK::RSA)
      expect(imported_jwk.verify_key.to_der).to eq(leaf_key.public_key.to_der)
    end

    it 'accepts the trusted root being repeated at the end of x5c' do
      jwk_params[:x5c] = [leaf_certificate, intermediate_certificate, root_certificate].map { |cert| Base64.strict_encode64(cert.to_der) }
      expect(imported_jwk.verify_key.to_der).to eq(leaf_key.public_key.to_der)
    end

    it 'provides a key that can verify tokens' do
      token = JWT.encode({ 'data' => 'something' }, leaf_key, 'RS256', kid: imported_jwk[:kid])
      jwks = JWT::JWK::Set.new([imported_jwk])
      expect(JWT.decode(token, nil, true, algorithms: ['RS256'], jwks: jwks).first).to eq('data' => 'something')
    end
  end

  context 'with a valid EC JWK carrying x5c' do
    let(:leaf_key) { OpenSSL::PKey::EC.generate('prime256v1') }
    let(:jwk_params) { JWT::JWK::EC.new(leaf_key).export.merge(x5c: x5c, x5t: x5t, 'x5t#S256': x5t_s256) }

    it 'imports the JWK and binds it to the leaf certificate key' do
      expect(imported_jwk).to be_a(JWT::JWK::EC)
      expect(imported_jwk.verify_key.public_key.to_bn).to eq(leaf_key.public_key.to_bn)
    end

    context 'when the JWK carries another valid EC public key' do
      let(:jwk_params) { JWT::JWK::EC.new(OpenSSL::PKey::EC.generate('prime256v1')).export.merge(x5c: x5c) }

      it 'raises a key mismatch error' do
        expect { imported_jwk }.to raise_error(JWT::CertificateKeyMismatchError, /does not match the JWK public key parameters/)
      end
    end
  end

  context 'when the x5c certificates are in the wrong order' do
    let(:x5c) { [intermediate_certificate, leaf_certificate].map { |cert| Base64.strict_encode64(cert.to_der) } }

    it 'raises a certificate chain error' do
      expect { imported_jwk }.to raise_error(JWT::CertificateChainError, /not in the expected order/)
    end
  end

  context 'when the JWK carries another valid RSA public key' do
    let(:jwk_params) { JWT::JWK::RSA.new(OpenSSL::PKey::RSA.new(2048)).export.merge(x5c: x5c) }

    it 'raises a key mismatch error' do
      expect { imported_jwk }.to raise_error(JWT::CertificateKeyMismatchError, /does not match the JWK public key parameters/)
    end
  end

  context 'when x5c chains to a root that is not trusted by the caller' do
    let(:rogue_root_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:rogue_root) { generate_root_certificate(OpenSSL::X509::Name.parse('/DC=org/DC=rogue/CN=Rogue Root'), rogue_root_key) }
    let(:leaf_certificate) do
      cert = build_certificate(leaf_dn, leaf_key, 3, issuer: rogue_root)
      cert.sign(rogue_root_key, 'sha256')
      cert
    end
    let(:x5c) { [leaf_certificate, rogue_root].map { |cert| Base64.strict_encode64(cert.to_der) } }

    it 'does not trust the root carried in x5c' do
      expect { imported_jwk }.to raise_error(JWT::CertificateChainError, /self-signed certificate in certificate chain/)
    end
  end

  context 'when x5t is not valid base64url' do
    let(:x5t) { '!!!not-valid!!!' }

    it 'raises a certificate thumbprint error' do
      expect { imported_jwk }.to raise_error(JWT::CertificateThumbprintError, /Invalid x5t value: not valid base64url/)
    end
  end

  context 'when x5t has the wrong digest length' do
    let(:x5t) { JWT::Base64.url_encode(OpenSSL::Digest::SHA256.digest(leaf_certificate.to_der)) }

    it 'raises a certificate thumbprint error' do
      expect { imported_jwk }.to raise_error(JWT::CertificateThumbprintError, /Invalid x5t value: expected a 20-byte digest/)
    end
  end

  context 'when x5t does not match the leaf certificate' do
    let(:x5t) { JWT::Base64.url_encode(OpenSSL::Digest::SHA1.digest(intermediate_certificate.to_der)) }

    it 'raises a certificate thumbprint error' do
      expect { imported_jwk }.to raise_error(JWT::CertificateThumbprintError, /The x5t thumbprint does not match/)
    end
  end

  context 'when x5t#S256 does not match the leaf certificate' do
    let(:x5t_s256) { JWT::Base64.url_encode(OpenSSL::Digest::SHA256.digest(intermediate_certificate.to_der)) }

    it 'raises a certificate thumbprint error' do
      expect { imported_jwk }.to raise_error(JWT::CertificateThumbprintError, /The x5t#S256 thumbprint does not match/)
    end
  end

  context 'when the chain uses a signature algorithm that is not allowed' do
    let(:binding_options) { { x5c: { root_certificates: [root_certificate], algorithms: ['ecdsa-with-SHA256'] } } }

    it 'raises a certificate chain error' do
      expect { imported_jwk }.to raise_error(JWT::CertificateChainError, /sha256WithRSAEncryption is not allowed/)
    end
  end

  context 'when the chain uses an allowed signature algorithm' do
    let(:binding_options) { { x5c: { root_certificates: [root_certificate], algorithms: ['sha256WithRSAEncryption'] } } }

    it 'imports the JWK' do
      expect(imported_jwk).to be_a(JWT::JWK::RSA)
    end
  end

  context 'when the verification time is before the chain becomes valid' do
    let(:binding_options) { { x5c: { root_certificates: [root_certificate], time: Time.now - 7200 } } }

    it 'raises a certificate chain error' do
      expect { imported_jwk }.to raise_error(JWT::CertificateChainError, /certificate is not yet valid/)
    end
  end

  context 'when the verification time is within the validity window' do
    let(:binding_options) { { x5c: { root_certificates: [root_certificate], time: Time.now + 1800 } } }

    it 'imports the JWK' do
      expect(imported_jwk).to be_a(JWT::JWK::RSA)
    end
  end

  context 'with CRLs' do
    let(:leaf_certificate) do
      cert = build_certificate(leaf_dn, leaf_key, 3, issuer: root_certificate)
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.config = OpenSSL::Config.parse("[crlDistPts]\nURI.1 = http://www.example.com/crl")
      ef.subject_certificate = cert
      cert.add_extension(ef.create_extension('crlDistributionPoints', '@crlDistPts'))
      cert.sign(root_key, 'sha256')
      cert
    end
    let(:x5c) { [Base64.strict_encode64(leaf_certificate.to_der)] }
    let(:crl) { issue_crl(revocations, issuer: root_certificate, issuer_key: root_key) }
    let(:binding_options) { { x5c: { root_certificates: [root_certificate], crls: [crl] } } }

    context 'when the leaf certificate is not revoked' do
      let(:revocations) { [] }

      it 'imports the JWK' do
        expect(imported_jwk).to be_a(JWT::JWK::RSA)
      end
    end

    context 'when the leaf certificate is revoked' do
      let(:revocations) { [[3, Time.now - 60, 1]] }

      it 'raises a certificate chain error' do
        expect { imported_jwk }.to raise_error(JWT::CertificateChainError, /certificate revoked/)
      end
    end
  end

  context 'when the JWK has no x5c member' do
    let(:jwk_params) { JWT::JWK::RSA.new(leaf_key).export }

    it 'imports the JWK as before' do
      expect(imported_jwk).to be_a(JWT::JWK::RSA)
    end
  end

  context 'when no x5c binding options are given' do
    let(:binding_options) { {} }
    let(:x5c) { ['broken'] }

    it 'imports the JWK without certificate validation' do
      expect(imported_jwk).to be_a(JWT::JWK::RSA)
    end
  end

  context 'when importing into a JWK::Set' do
    context 'with a JWK that fails the certificate binding' do
      let(:jwk_params) { JWT::JWK::RSA.new(OpenSSL::PKey::RSA.new(2048)).export.merge(x5c: x5c) }

      it 'raises and does not let the JWK into the set' do
        expect { JWT::JWK::Set.new([jwk_params], binding_options) }.to raise_error(JWT::CertificateKeyMismatchError)
      end
    end

    context 'with a valid JWK' do
      it 'adds the JWK to the set' do
        jwks = JWT::JWK::Set.new([jwk_params], binding_options)
        expect(jwks.size).to eq(1)
        expect(jwks.first.verify_key.to_der).to eq(leaf_key.public_key.to_der)
      end
    end
  end

  private

  def generate_root_certificate(name, key)
    cert = build_certificate(name, key, 1, issuer: nil)
    cert.add_extension(extension_factory.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.sign(key, 'sha256')
    cert
  end

  def extension_factory
    OpenSSL::X509::ExtensionFactory.new
  end

  def build_certificate(name, key, serial, issuer:)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = name
    cert.issuer = issuer ? issuer.subject : name
    cert.public_key = key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 3600
    cert
  end

  def issue_crl(revocations, issuer:, issuer_key:)
    crl = OpenSSL::X509::CRL.new
    crl.issuer = issuer.subject
    crl.version = 1
    crl.last_update = Time.now - 3600
    crl.next_update = Time.now + 3600
    revocations.each { |serial, time, reason| crl.add_revoked(build_revoked(serial, time, reason)) }
    crl.add_extension(OpenSSL::X509::Extension.new('crlNumber', OpenSSL::ASN1::Integer(1)))
    crl.sign(issuer_key, 'sha256')
    crl
  end

  def build_revoked(serial, time, reason)
    revoked = OpenSSL::X509::Revoked.new
    revoked.serial = serial
    revoked.time = time
    revoked.add_extension(OpenSSL::X509::Extension.new('CRLReason', OpenSSL::ASN1::Enumerated(reason)))
    revoked
  end
end
