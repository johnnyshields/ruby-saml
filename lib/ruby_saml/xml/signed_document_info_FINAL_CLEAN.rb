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

      # Get the hash algorithm of the SignatureMethod
      # @return [OpenSSL::Digest] The signature hash algorithm
      def signature_hash_algorithm
        sig_alg_value = signed_info_node.at_xpath(
          './ds:SignatureMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        RubySaml::XML.hash_algorithm(sig_alg_value)
      end

      # Get the decoded SignatureValue text
      # @return [String, nil] The decoded signature value
      def signature_value
        base64_signature = signature_node.at_xpath(
          './ds:SignatureValue',
          { 'ds' => RubySaml::XML::DSIG }
        )&.text&.strip
        raise RubySaml::ValidationError.new('No Signature Value found') if base64_signature.nil?

        Base64.decode64(base64_signature)
      end

      def canonicalized_signed_info_node
        signed_info_node = signed_info_node.canonicalize(canon_algorithm_from_signed_info)
        # .to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
        Nokogiri::XML(signed_info_node).root
      end

      def reference_node
        signed_info_node.at_xpath('./ds:Reference', { 'ds' => RubySaml::XML::DSIG }) ||
          (raise RubySaml::ValidationError.new('No Reference node found'))
      end

      def canonicalized_subject_node
        noko.at_xpath("//*[@ID='#{subject_id}']")&.canonicalize(canon_algorithm, inclusive_namespaces) ||
          (raise RubySaml::ValidationError.new('No subject node found'))
      end

      private

      # Get the ID of the signed element
      # @return [String, nil] The ID of the signed element
      def subject_id
        id = uri_from_reference_node || signature_node.parent['ID']
        return id unless !id || id.empty?
        raise RubySaml::ValidationError.new('No signed subject ID found')
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

      # Extract inclusive namespaces from the document
      # @return [Array<String>, nil] The inclusive namespaces
      def inclusive_namespaces
        noko.at_xpath(
          '//ec:InclusiveNamespaces',
          { 'ec' => RubySaml::XML::C14N }
        )&.[]('PrefixList')&.value&.split
      end

      # def memoize(name)
      #   name = "@#{name.to_s.delete_prefix('@')}"
      #   return instance_variable_get(name) if instance_variable_defined?(name)
      #
      #   instance_variable_set(name, yield)
      # end
    end
  end
end
