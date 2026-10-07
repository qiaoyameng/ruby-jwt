# frozen_string_literal: true

module JWT
  module JWK
    # Optional binding check between a JWK and the X.509 certificate material
    # it carries. When a JWK contains an "x5c" certificate chain, the chain is
    # verified against caller provided trust roots (and optionally CRLs, a
    # verification time and a list of allowed certificate signature
    # algorithms), the leaf certificate public key is compared against the
    # public key parameters of the JWK ("n"/"e" for RSA, "crv"/"x"/"y"
    # for EC) and the "x5t" and "x5t#S256" thumbprints, when present, are
    # compared against the digest of the leaf certificate DER encoding.
    #
    # All verification is done locally; no certificate URLs are accessed.
    # See https://tools.ietf.org/html/rfc7517#section-4.7
    class CertificateBinding # rubocop:disable Metrics/ClassLength
      THUMBPRINT_DIGESTS = {
        x5t: OpenSSL::Digest::SHA1,
        'x5t#S256': OpenSSL::Digest::SHA256
      }.freeze

      def initialize(root_certificates:, crls: nil, time: nil, allowed_algorithms: nil)
        raise ArgumentError, 'Root certificates must be specified' unless root_certificates

        @root_certificates = root_certificates
        @crls = crls
        @time = time
        @allowed_algorithms = allowed_algorithms
      end

      # Verifies the certificate binding of the given JWK. JWKs without an
      # "x5c" parameter are accepted as-is.
      #
      # @param jwk [JWT::JWK::KeyBase] the JWK to verify
      # @return [true] when the binding is valid or no "x5c" parameter is present
      # @raise [JWT::CertificateChainError] when the certificate chain is invalid
      # @raise [JWT::CertificateKeyMismatchError] when the leaf certificate key differs from the JWK public parameters
      # @raise [JWT::CertificateThumbprintError] when a thumbprint is malformed or does not match
      def verify!(jwk)
        x5c = jwk[:x5c]
        return true if x5c.nil? || x5c.empty?

        certificates = parse_certificates(x5c)
        verify_certificate_order!(certificates)
        verify_chain!(certificates)
        verify_signature_algorithms!(certificates)
        verify_key_binding!(jwk, certificates.first)
        verify_thumbprints!(jwk, certificates.first)
        true
      end

      private

      def parse_certificates(x5c)
        x5c.map do |encoded|
          encoded.is_a?(OpenSSL::X509::Certificate) ? encoded : OpenSSL::X509::Certificate.new(::JWT::Base64.url_decode(encoded))
        end
      rescue OpenSSL::X509::CertificateError, JWT::Base64DecodeError => e
        raise CertificateChainError, "Unable to parse the x5c certificate chain: #{e.message}"
      end

      # RFC 7517 requires the leaf certificate to be first, directly followed
      # by the certificates that certified it.
      def verify_certificate_order!(certificates)
        certificates.each_cons(2) do |certificate, issuer|
          next if certificate.issuer == issuer.subject && certificate.verify(issuer.public_key)

          raise CertificateChainError,
                'Certificates in the x5c parameter are not in order: each certificate must be directly certified by the next one'
        end
      end

      def verify_chain!(certificates)
        signing_certificate, *certificate_chain = certificates
        store_context = OpenSSL::X509::StoreContext.new(@store ||= build_store, signing_certificate, certificate_chain)
        return if store_context.verify

        error = "Certificate verification failed: #{store_context.error_string}."
        if (current_cert = store_context.current_cert)
          error = "#{error} Certificate subject: #{current_cert.subject}."
        end

        raise CertificateChainError, error
      end

      def verify_signature_algorithms!(certificates)
        return unless @allowed_algorithms

        certificates.each do |certificate|
          next if @allowed_algorithms.include?(certificate.signature_algorithm)

          raise CertificateChainError,
                "Certificate signature algorithm #{certificate.signature_algorithm} is not allowed. Certificate subject: #{certificate.subject}."
        end
      end

      def verify_key_binding!(jwk, leaf_certificate)
        return if public_key_matches?(jwk, leaf_certificate.public_key)

        raise CertificateKeyMismatchError,
              'The public key of the leaf certificate does not match the public key parameters of the JWK'
      end

      def verify_thumbprints!(jwk, leaf_certificate)
        THUMBPRINT_DIGESTS.each do |parameter, digest_class|
          thumbprint = jwk[parameter]
          next unless thumbprint

          verify_thumbprint!(parameter, thumbprint, digest_class, leaf_certificate)
        end
      end

      def verify_thumbprint!(parameter, thumbprint, digest_class, leaf_certificate)
        return if decode_thumbprint(parameter, thumbprint, digest_class) == digest_class.digest(leaf_certificate.to_der)

        raise CertificateThumbprintError,
              "The #{parameter} parameter does not match the digest of the leaf certificate"
      end

      def decode_thumbprint(parameter, thumbprint, digest_class)
        decoded = ::JWT::Base64.url_decode(thumbprint)
        digest_length = digest_class.new.digest_length
        return decoded if decoded.bytesize == digest_length

        raise CertificateThumbprintError,
              "The #{parameter} parameter has an invalid encoding: expected #{digest_length} bytes, got #{decoded.bytesize}"
      rescue JWT::Base64DecodeError
        raise CertificateThumbprintError, "The #{parameter} parameter is not valid base64url"
      end

      def public_key_matches?(jwk, certificate_key)
        case jwk
        when JWT::JWK::RSA
          certificate_key.is_a?(OpenSSL::PKey::RSA) &&
            certificate_key.n == jwk.keypair.n &&
            certificate_key.e == jwk.keypair.e
        when JWT::JWK::EC
          certificate_key.is_a?(OpenSSL::PKey::EC) &&
            certificate_key.group.curve_name == jwk.keypair.group.curve_name &&
            certificate_key.public_key.to_bn(:uncompressed) == jwk.keypair.public_key.to_bn(:uncompressed)
        else
          false
        end
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
    end
  end
end
