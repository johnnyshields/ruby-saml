# frozen_string_literal: true

module RubySaml
  module XML
    class SignedDocumentInfo
      attr_reader :noko,
                  :check_malformed_doc

      # Represents the information extracted from a signed document.
      # Intended to avoid signature wrapping attacks.
      #
      # @param noko [Nokogiri::XML] The XML document to validate
      # @param check_malformed_doc [Boolean] Whether to check for malformed documents
      def initialize(noko, check_malformed_doc: true)
        @noko = noko
        @check_malformed_doc = check_malformed_doc
      end

      # Get the signature hash algorithm
      # @return [OpenSSL::Digest] The signature hash algorithm
      def signature_hash_algorithm
        sig_alg_value = signed_info_node.at_xpath(
          './ds:SignatureMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        RubySaml::XML.hash_algorithm(sig_alg_value)
      end

      # Get the decoded SignatureValue
      # @return [String] The decoded signature value
      def signature_value
        base64_signature = signature_node.at_xpath(
          './ds:SignatureValue',
          { 'ds' => RubySaml::XML::DSIG }
        )&.text&.strip
        raise RubySaml::ValidationError.new('No Signature Value found') if base64_signature.nil?

        Base64.decode64(base64_signature)
      end

      # Get the canonicalized SignedInfo element
      # @return [String] The canonicalized SignedInfo element
      def canonicalized_signed_info
        signed_info_node.canonicalize(canon_algorithm_from_signed_info)
      end

      # Get the Reference node
      # @return [Nokogiri::XML::Element] The Reference node
      def reference_node
        signed_info_node.at_xpath('./ds:Reference', { 'ds' => RubySaml::XML::DSIG }) ||
          (raise RubySaml::ValidationError.new('No Reference node found'))
      end

      # Get the canonicalized subject node (the node being signed)
      # @return [String] The canonicalized subject
      def canonicalized_subject
        subject_node = noko.at_xpath("//*[@ID='#{subject_id}']") ||
          (raise RubySaml::ValidationError.new('No subject node found'))
        subject_node.canonicalize(canon_algorithm, inclusive_namespaces)
      end

      # Get the digest algorithm
      # @return [OpenSSL::Digest] The digest algorithm
      def digest_algorithm
        digest_method_node = reference_node.at_xpath(
          './ds:DigestMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        RubySaml::XML.hash_algorithm(digest_method_node)
      end

      # Get the decoded DigestValue
      # @return [String] The decoded digest value
      def digest_value
        encoded_digest = reference_node.at_xpath(
          './ds:DigestValue',
          { 'ds' => RubySaml::XML::DSIG }
        )&.text&.strip
        raise RubySaml::ValidationError.new('No DigestValue found') if encoded_digest.nil?

        Base64.decode64(encoded_digest)
      end

      # Get the ID of the signed element
      # @return [String] The ID of the signed element
      def subject_id
        id = uri_from_reference_node || signature_node.parent['ID']
        return id unless !id || id.empty?
        raise RubySaml::ValidationError.new('No signed subject ID found')
      end

      # Extract inclusive namespaces from the document
      # @return [Array<String>, nil] The inclusive namespaces
      def inclusive_namespaces
        noko.at_xpath(
          '//ec:InclusiveNamespaces',
          { 'ec' => RubySaml::XML::C14N }
        )&.[]('PrefixList')&.split
      end

      private

      # Get the ds:Signature element from the document
      # @return [Nokogiri::XML::Element] The Signature element
      def signature_node
        noko.at_xpath(
          '//ds:Signature',
          { 'ds' => RubySaml::XML::DSIG }
        ) || (raise RubySaml::ValidationError.new('No Signature node found'))
      end

      # Get the ds:SignedInfo element from the document
      # @return [Nokogiri::XML::Element] The SignedInfo element
      def signed_info_node
        signature_node.at_xpath('./ds:SignedInfo', 'ds' => RubySaml::XML::DSIG) ||
          (raise RubySaml::ValidationError.new('No SignedInfo node found'))
      end

      def canon_algorithm
        canon_algorithm_from_transforms || canon_algorithm_from_signed_info
      end

      def canon_algorithm_from_signed_info
        canon_method_node = signed_info_node.at_xpath(
          './ds:CanonicalizationMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        RubySaml::XML.canon_algorithm(canon_method_node)
      end

      def canon_algorithm_from_transforms
        transforms = reference_node.xpath('./ds:Transforms/ds:Transform', { 'ds' => RubySaml::XML::DSIG })
        transform_element = transforms.reverse.detect {|transform_element| transform_element['Algorithm'] }
        RubySaml::XML.canon_algorithm(transform_element, default: false)
      end

      def uri_from_reference_node
        uri = reference_node&.[]('URI')&.delete_prefix('#')
        uri unless !uri || uri.empty?
      end
    end
  end
end
