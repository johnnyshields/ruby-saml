# frozen_string_literal: true

require 'ruby_saml/error_handling'
require 'ruby_saml/utils'

module RubySaml
  module XML
    module SignedDocumentValidator
      extend self

      def with_error_handling(errors, soft)
        yield
      rescue RubySaml::ValidationError => e
        errors << e.message
        raise e unless soft
        errors # TODO: Return false??
      end

      # TODO: [ERRORS-REFACTOR] -- Rather than returning array of error,
      # raise actual error classes
      def validate_document(document, idp_cert_fingerprint, errors = [], soft: true, **options)
        with_error_handling(errors, soft) do
          SignedDocumentInfo.new(document).validate_document(idp_cert_fingerprint, options)
        end
      end

      def validate_document_with_cert(document, idp_cert, errors = [], soft: true)
        with_error_handling(errors, soft) do
          SignedDocumentInfo.new(document).validate_document_with_cert(idp_cert)
        end
      end

      def validate_signature(document, base64_cert, errors = [], soft: true)
        with_error_handling(errors, soft) do
          SignedDocumentInfo.new(document).validate_signature(base64_cert)
        end
      end

      # TODO: This is a workaround to avoid errors
      def subject_id(noko)
        # TODO: Should be this
        # SignedDocumentInfo.new(document).subject_id
        noko = RubySaml::XML.safe_load_nokogiri(noko) unless noko.is_a?(Nokogiri::XML::Document)
        reference_element = noko.at_xpath(
          '//ds:Signature/ds:SignedInfo/ds:Reference',
          { 'ds' => RubySaml::XML::DSIG }
        )

        return nil if reference_element.nil?

        sei = reference_element['URI'].delete_prefix('#')
        return sei unless !sei || sei.empty?

        reference_element.parent.parent.parent['ID']
      end

      def subject_node(document)
        SignedDocumentInfo.new(document).subject_node
      end
    end
  end
end
