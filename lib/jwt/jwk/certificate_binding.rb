# frozen_string_literal: true

module JWT
  module JWK
    # Validates the binding between a JWK and its X.509 certificate material.
    #
    # When a JWK carries public key parameters (n/e or crv/x/y) alongside an
    # x5c certificate chain and certificate thumbprints (x5t, x5t#S256), all
    # of them must describe the same key. This validator:
    #
    # 1. Verifies the x5c certificate chain against caller-provided trusted
    #    root certificates (and CRLs, when given) at a caller-provided
    #    verification time. Certificates carried in x5c itself are never
    #    added to the trust store.
    # 2. Ensures the certificates in x5c are in the expected order (leaf
    #    first, each certificate issued by the next one).
    # 3. Ensures the chain only uses caller-allowed signature algorithms.
    # 4. Ensures the leaf certificate public key matches the JWK public key
    #    parameters.
    # 5. Ensures x5t (SHA-1) and x5t#S256 (SHA-256), when present, match the
    #    DER digest of the leaf certificate.
    #
    # The whole process is offline: no certificate or CRL URLs are fetched.
    class CertificateBinding
      # Digest used for each thumbprint member.
      # See RFC 7515 sections 4.1.7 and 4.1.8.
      THUMBPRINT_DIGESTS = {
        x5t: OpenSSL::Digest::SHA1,
        'x5t#S256': OpenSSL::Digest::SHA256
      }.freeze

      def initialize(root_certificates:, crls: nil, time: nil, algorithms: nil)
        raise ArgumentError, 'Root certificates must be specified' unless root_certificates

        @root_certificates = root_certificates
        @crls = crls
        @time = time
        @algorithms = algorithms
      end

      # Validates the certificate material of the given JWK.
      #
      # @param jwk [JWT::JWK::KeyBase] the JWK to validate.
      # @return [JWT::JWK::KeyBase] the given JWK, when valid.
      # @raise [JWT::CertificateChainError] when the x5c chain is invalid.
      # @raise [JWT::CertificateKeyMismatchError] when the leaf certificate
      #         public key does not match the JWK public key parameters.
      # @raise [JWT::CertificateThumbprintError] when a certificate thumbprint
      #         is malformed or does not match the leaf certificate.
      def validate(jwk)
        certificates = parse_certificates(jwk[:x5c])

        verify_certificate_order!(certificates)
        verify_chain!(certificates.first, certificates.drop(1))
        verify_signature_algorithms!(certificates)
        verify_public_key_binding!(jwk, certificates.first)
        verify_thumbprints!(jwk, certificates.first)

        jwk
      end

      private

      def parse_certificates(x5c)
        certificates = Array(x5c).map do |encoded|
          encoded.is_a?(OpenSSL::X509::Certificate) ? encoded : OpenSSL::X509::Certificate.new(::JWT::Base64.url_decode(encoded))
        end

        raise JWT::CertificateChainError, 'The x5c parameter does not contain any certificates' if certificates.empty?

        certificates
      rescue OpenSSL::X509::CertificateError => e
        raise JWT::CertificateChainError, "Invalid certificate in the x5c parameter: #{e.message}"
      end

      def verify_certificate_order!(certificates)
        certificates.each_cons(2) do |certificate, issuer|
          next if certificate.issuer == issuer.subject

          raise JWT::CertificateChainError,
                "The x5c certificates are not in the expected order: #{certificate.subject} is not issued by #{issuer.subject}"
        end
      end

      def verify_chain!(leaf_certificate, chain_certificates)
        store_context = OpenSSL::X509::StoreContext.new(build_store, leaf_certificate, chain_certificates)
        return if store_context.verify

        error = "Certificate verification failed: #{store_context.error_string}."
        if (current_cert = store_context.current_cert)
          error = "#{error} Certificate subject: #{current_cert.subject}."
        end

        raise JWT::CertificateChainError, error
      end

      def build_store
        store = OpenSSL::X509::Store.new
        store.purpose = OpenSSL::X509::PURPOSE_ANY
        store.time = @time if @time
        if @crls
          store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
          @crls.each { |crl| store.add_crl(crl) }
        end
        @root_certificates.each { |certificate| store.add_cert(certificate) }
        store
      end

      def verify_signature_algorithms!(certificates)
        return unless @algorithms

        certificates.each do |certificate|
          next if @algorithms.include?(certificate.signature_algorithm)

          raise JWT::CertificateChainError,
                "Certificate signature algorithm #{certificate.signature_algorithm} is not allowed. Certificate subject: #{certificate.subject}."
        end
      end

      def verify_public_key_binding!(jwk, leaf_certificate)
        certificate_jwk = JWT::JWK.create_from(leaf_certificate.public_key)
        return if certificate_jwk.members == jwk.members

        raise JWT::CertificateKeyMismatchError,
              'The leaf certificate public key does not match the JWK public key parameters'
      end

      def verify_thumbprints!(jwk, leaf_certificate)
        THUMBPRINT_DIGESTS.each do |member, digest_class|
          encoded = jwk[member]
          next unless encoded

          verify_thumbprint!(member, encoded, digest_class.digest(leaf_certificate.to_der))
        end
      end

      def verify_thumbprint!(member, encoded, expected_digest)
        digest = decode_thumbprint(member, encoded)

        if digest.bytesize != expected_digest.bytesize
          raise JWT::CertificateThumbprintError,
                "Invalid #{member} value: expected a #{expected_digest.bytesize}-byte digest, got #{digest.bytesize} bytes"
        end

        return if digest == expected_digest

        raise JWT::CertificateThumbprintError,
              "The #{member} thumbprint does not match the leaf certificate"
      end

      def decode_thumbprint(member, encoded)
        ::JWT::Base64.url_decode(encoded)
      rescue JWT::Base64DecodeError
        raise JWT::CertificateThumbprintError, "Invalid #{member} value: not valid base64url"
      end
    end
  end
end
