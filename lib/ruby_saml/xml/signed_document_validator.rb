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
      end

      # TODO: [ERRORS-REFACTOR] -- Rather than returning array of error,
      # raise actual error classes
      def validate_document(document, idp_cert_fingerprint, errors = [], soft: true, **options)
        with_error_handling(errors, soft) do
          SignedDocument.validate_document(document.to_s, idp_cert_fingerprint, options)
        end
      end

      def validate_document_with_cert(document, idp_cert, errors = [], soft: true)
        with_error_handling(errors, soft) do
          SignedDocument.validate_document_with_cert(document.to_s, idp_cert)
        end
      end

      def validate_signature(document, base64_cert, errors = [], soft: true)
        with_error_handling(errors, soft) do
          SignedDocument.validate_signature(document.to_s, base64_cert)
        end
      end

      def extract_signed_element_id(document)
        SignedDocument.extract_signed_element_id(document.to_s)

        # noko = RubySaml::XML.safe_load_nokogiri(document.to_s)
        #
        # reference_element = noko.at_xpath(
        #   '//ds:Signature/ds:SignedInfo/ds:Reference',
        #   { 'ds' => RubySaml::XML::DSIG }
        # )
        #
        # return nil if reference_element.nil?
        #
        # uri = reference_element['URI']
        # return nil unless uri
        #
        # sei = uri[1..]  # Remove the leading '#'
        # sei.nil? ? reference_element.parent.parent.parent['ID'] : sei
      end

      # def referenced_xml(document)
      #   doc = SignedDocument.new(document.to_s)
      #   doc.cache_referenced_xml(true)
      #   doc.referenced_xml
      # end

      private

      def process_transforms(ref, canon_algorithm)
        transforms = ref.xpath(
          './ds:Transforms/ds:Transform',
          { 'ds' => RubySaml::XML::DSIG }
        )

        transforms.each do |transform_element|
          next unless transform_element['Algorithm']

          canon_algorithm = RubySaml::XML.canon_algorithm(transform_element, default: false)
        end

        canon_algorithm
      end

      def digests_match?(hash, digest_value)
        hash == digest_value
      end

      def extract_inclusive_namespaces(document)
        noko = RubySaml::XML.safe_load_nokogiri(document.to_s)

        element = noko.at_xpath(
          '//ec:InclusiveNamespaces',
          { 'ec' => RubySaml::XML::C14N }
        )
        return unless element

        prefix_list = element['PrefixList']
        prefix_list.split
      end
    end
  end
end
