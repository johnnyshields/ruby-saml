# frozen_string_literal: true

module RubySaml
  module XML
    class SignedDocument
      attr_reader :noko,
                  :check_malformed_doc,
                  :document_info

      def initialize(noko, check_malformed_doc: true)
        @noko = noko
        @check_malformed_doc = check_malformed_doc
        @document_info = SignedDocumentInfo.new(noko, check_malformed_doc: check_malformed_doc)
      end

      def signed_element_id
        @signed_element_id ||= document_info.subject_id
      end

      # Validates the subject_node, which is the signed part of the document
      def validate_document(idp_cert_fingerprint = true, options = {})
        # get cert from response
        cert_element = REXML::XPath.first(
          self,
          '//ds:X509Certificate',
          { 'ds' => RubySaml::XML::DSIG }
        )

        if cert_element
          base64_cert = RubySaml::Utils.element_text(cert_element)
          cert_text = Base64.decode64(base64_cert)
          begin
            cert = OpenSSL::X509::Certificate.new(cert_text)
          rescue OpenSSL::X509::CertificateError => _e
            raise RubySaml::ValidationError.new('Document Certificate Error')
          end

          if options[:fingerprint_alg]
            fingerprint_alg = RubySaml::XML.hash_algorithm(options[:fingerprint_alg]).new
          else
            fingerprint_alg = OpenSSL::Digest.new('SHA256')
          end
          fingerprint = fingerprint_alg.hexdigest(cert.to_der)

          # check cert matches registered idp cert
          if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/, '').downcase
            raise RubySaml::ValidationError.new('Fingerprint mismatch')
          end

          base64_cert = Base64.strict_encode64(cert.to_der)
        elsif options[:cert]
          base64_cert = Base64.strict_encode64(options[:cert].to_pem)
        else
          raise RubySaml::ValidationError.new('Certificate element missing in response (ds:X509Certificate) and not cert provided at settings')
        end

        validate_signature(base64_cert)
      end

      def validate_document_with_cert(idp_cert = true)
        # get cert from response
        cert_element = REXML::XPath.first(
          self,
          '//ds:X509Certificate',
          { 'ds' => RubySaml::XML::DSIG }
        )

        if cert_element
          base64_cert = RubySaml::Utils.element_text(cert_element)
          cert_text = Base64.decode64(base64_cert)
          begin
            cert = OpenSSL::X509::Certificate.new(cert_text)
          rescue OpenSSL::X509::CertificateError => _e
            raise RubySaml::ValidationError.new('Document Certificate Error')
          end

          # check saml response cert matches provided idp cert
          if idp_cert.to_pem != cert.to_pem
            raise RubySaml::ValidationError.new('Certificate of the Signature element does not match provided certificate')
          end
        end

        encoded_idp_cert = Base64.strict_encode64(idp_cert.to_pem)
        validate_signature(encoded_idp_cert)
      end

      def validate_signature(base64_cert)
        # Get certificate object
        cert_text = Base64.decode64(base64_cert)
        cert = OpenSSL::X509::Certificate.new(cert_text)

        # Get required information from document_info
        signature = document_info.signature_value
        hash_algorithm = document_info.signature_hash_algorithm
        signed_info = document_info.canonicalized_signed_info

        # Get reference and digest information
        subject_node = document_info.canonicalized_subject_node
        digest_algorithm = document_info.digest_algorithm
        digest_value = document_info.digest_value

        # Calculate digest of referenced XML
        calculated_digest = digest_algorithm.digest(subject_node)

        # Compare digests
        unless calculated_digest == digest_value
          raise RubySaml::ValidationError.new('Digest mismatch')
        end

        # Verify signature
        signature_verified = false
        begin
          signature_verified = cert.public_key.verify(hash_algorithm.new, signature, signed_info)
        rescue OpenSSL::PKey::PKeyError # rubocop:disable Lint/SuppressedException
        end

        raise RubySaml::ValidationError.new('Key validation error') unless signature_verified

        true
      end
    end
  end
end
