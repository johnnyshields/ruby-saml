# frozen_string_literal: true

module RubySaml
  # TODO: Move these elsewhere
  module XMLProcessing
    # SAML namespaces for XPath
    SAML_NAMESPACES = {
      'p' => RubySaml::XML::NS_PROTOCOL,
      'a' => RubySaml::XML::NS_ASSERTION,
      'ds' => RubySaml::XML::DSIG
    }.freeze

    # Parse a time attribute
    def parse_time(node, attribute)
      return unless (value = node&.[](attribute))
      Time.parse(value)
    end

    # Extract elements with XPath
    def xpath_extract(document, xpath)
      document.xpath(xpath, SAML_NAMESPACES)
    end

    # Extract a single element with XPath
    def xpath_first(document, xpath)
      document.at_xpath(xpath, SAML_NAMESPACES)
    end

    # Create SAML document with metadata
    def create_xml_document(root_name, attributes, &block)
      builder = Nokogiri::XML::Builder.new do |xml|
        xml['samlp'].send(root_name, clean_attributes(attributes), &block)
      end

      builder.doc
    end

    # Sign a document
    def sign_document(document, settings, security_option)
      cert, private_key = settings.get_sp_signing_pair
      binding = binding_type(settings)

      if binding == Utils::BINDINGS[:post] &&
        settings.security[security_option] &&
        private_key &&
        cert
        RubySaml::XML::DocumentSigner.sign_document!(
          document,
          private_key,
          cert,
          settings.get_sp_signature_method,
          settings.get_sp_digest_method
        )
      else
        document
      end
    end

    # Validate document signature
    def validate_signature(document, idp_certs, idp_cert, fingerprint, check_expiration: false)
      old_errors = @errors.clone
      valid = false
      expired = false

      if idp_certs.nil? || idp_certs[:signing].empty?
        # Single cert validation
        opts = {
          cert: idp_cert,
          fingerprint_alg: @settings&.idp_cert_fingerprint_algorithm
        }

        valid = RubySaml::XML::SignedDocumentValidator.validate_document(
          document, fingerprint, @errors, soft: @soft, **opts
        )

        if valid && check_expiration && RubySaml::Utils.is_cert_expired(idp_cert)
          expired = true
        end
      else
        # Multi-cert validation
        idp_certs[:signing].each do |cert|
          valid = RubySaml::XML::SignedDocumentValidator.validate_document_with_cert(
            document, cert, @errors, soft: @soft
          )

          next unless valid

          if check_expiration && RubySaml::Utils.is_cert_expired(cert)
            expired = true
          end

          @errors = old_errors
          break
        end
      end

      if expired
        return append_error("IdP x509 certificate expired", @soft)
      end

      unless valid
        @errors = @errors.uniq
        return false
      end

      true
    end
  end
end
