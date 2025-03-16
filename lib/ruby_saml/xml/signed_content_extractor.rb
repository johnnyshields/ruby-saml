# frozen_string_literal: true

module RubySaml
  module XML
    module ReferencedNodeExtractor
      extend self

      def extract_body_node(noko, check_malformed_doc: true)
        unless noko.is_a?(Nokogiri::XML::Document)
          begin
            noko = RubySaml::XML.safe_load_nokogiri(document.to_s, check_malformed_doc: check_malformed_doc)
          rescue StandardError => e
            raise RubySaml::ValidationError.new("XML load failed: #{e.message}")
          end
        end

        signature_node = noko.at_xpath(
          '//ds:Signature',
          { 'ds' => RubySaml::XML::DSIG }
        )
        return if signature_node.nil?

        signed_info_node = signature_node.at_xpath('./ds:SignedInfo', 'ds' => RubySaml::XML::DSIG)
        canon_algorithm = extract_canon_algorithm(signed_info_node)
        signed_info_node = signed_info_node.canonicalize(canon_algorithm)
        signed_info_node = Nokogiri::XML(signed_info_node.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)).root

        # Remove the signature element from the document
        signature_node.remove

        # check digests
        reference_node = signed_info_node.at_xpath('./ds:Reference', { 'ds' => RubySaml::XML::DSIG })
        return if reference_node.nil?

        signed_element_id = extract_uri(reference_node) || signature_node.parent['ID']
        body_node = noko.at_xpath("//*[@ID='#{signed_element_id}']")
        return if body_node.nil?

        canon_algorithm = process_transforms(reference_node, canon_algorithm)
        inclusive_namespaces = extract_inclusive_namespaces(noko)

        [body_node.canonicalize(canon_algorithm, inclusive_namespaces), signature_node]
      end

      private

      def extract_canon_algorithm(signed_info_node)
        canon_method_node = signed_info_node.at_xpath(
          './ds:CanonicalizationMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        RubySaml::XML.canon_algorithm(canon_method_node)
      end

      def process_transforms(reference_node, canon_algorithm)
        transforms = reference_node.xpath('./ds:Transforms/ds:Transform', { 'ds' => RubySaml::XML::DSIG })

        # TODO: This should just be a reverse_each
        transforms.each do |transform_element|
          algorithm_attr = transform_element['Algorithm']
          next unless algorithm_attr

          canon_algorithm = RubySaml::XML.canon_algorithm(transform_element, default: false)
        end

        canon_algorithm
      end

      # def extract_inclusive_namespaces(doc)
      #   element = doc.at_xpath(
      #     '//ec:InclusiveNamespaces',
      #     { 'ec' => RubySaml::XML::C14N }
      #   )
      #   return unless element
      #
      #   element['PrefixList']&.split
      # end

      def extract_uri(reference_node)
        uri = reference_node&.[]('URI')
        return nil unless uri

        uri = uri[1..] if uri.start_with?('#')
        uri unless uri.empty?
      end
    end
  end
end
