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

      # Validates the document using a fingerprint
      # @param idp_cert_fingerprint [String] The fingerprint to validate against
      # @param options [Hash] Options for validation
      # @return [Boolean] True if the document is valid
      def validate_document(idp_cert_fingerprint = true, options = {})
        base64_cert = if cert_from_response
                        cert = extract_certificate(cert_from_response.text.strip)

                        # Verify fingerprint matches
                        fingerprint = calculate_fingerprint(cert, options[:fingerprint_alg])
                        unless fingerprint == normalize_fingerprint(idp_cert_fingerprint)
                          raise RubySaml::ValidationError.new('Fingerprint mismatch')
                        end

                        Base64.strict_encode64(cert.to_der)
                      elsif options[:cert]
                        Base64.strict_encode64(options[:cert].to_pem)
                      else
                        raise RubySaml::ValidationError.new('Certificate element missing in response (ds:X509Certificate) and not cert provided at settings')
                      end

        validate_signature(base64_cert)
      end

      # Validates the document using a certificate
      # @param idp_cert [OpenSSL::X509::Certificate] The certificate to validate against
      # @return [Boolean] True if the document is valid
      def validate_document_with_cert(idp_cert = true)
        if cert_from_response
          cert = extract_certificate(cert_from_response.text.strip)

          # Check if certificates match
          unless idp_cert.to_pem == cert.to_pem
            raise RubySaml::ValidationError.new('Certificate of the Signature element does not match provided certificate')
          end
        end

        encoded_idp_cert = Base64.strict_encode64(idp_cert.to_pem)
        validate_signature(encoded_idp_cert)
      end

      # Validates the signature using a base64-encoded certificate
      # @param base64_cert [String] The base64-encoded certificate
      # @return [Boolean] True if the signature is valid
      def validate_signature(base64_cert = true)
        verify_signature_prerequisites

        # Get certificate object
        cert = extract_certificate(base64_cert)

        # Verify digest
        verify_digest_value

        # Verify signature
        unless verify_signature_with_cert(cert)
          raise RubySaml::ValidationError.new('Key validation error')
        end

        true
      end

      # Get the signature element from the document
      # @return [Nokogiri::XML::Element, nil] The signature element
      def signature_element
        @signature_element ||= noko.at_xpath(
          '//ds:Signature',
          { 'ds' => RubySaml::XML::DSIG }
        )
      end

      # Get the signature hash algorithm
      # @return [OpenSSL::Digest, nil] The signature hash algorithm
      def signature_hash_algorithm
        @signature_hash_algorithm ||= begin
                                        return nil if signature_element.nil?

                                        sig_alg_value = signature_element.at_xpath(
                                          './ds:SignedInfo/ds:SignatureMethod',
                                          { 'ds' => RubySaml::XML::DSIG }
                                        )
                                        RubySaml::XML.hash_algorithm(sig_alg_value)
                                      end
      end

      # Get the signature value
      # @return [String, nil] The decoded signature value
      def signature
        @signature ||= begin
                         return nil if signature_element.nil?

                         base64_signature = signature_element.at_xpath(
                           './ds:SignatureValue',
                           { 'ds' => RubySaml::XML::DSIG }
                         )
                         return nil if base64_signature.nil?

                         base64_signature_text = base64_signature.text.strip
                         base64_signature_text.nil? ? nil : Base64.decode64(base64_signature_text)
                       end
      end

      # Get the canonicalized SignedInfo element
      # @return [String, nil] The canonicalized SignedInfo
      # def cached_signed_info
      #   @cached_signed_info ||= begin
      #                             return nil if signature_element.nil?
      #
      #                             noko_sig_element = signature_element.dup
      #                             noko_signed_info_element = noko_sig_element.at_xpath(
      #                               './ds:SignedInfo',
      #                               'ds' => RubySaml::XML::DSIG
      #                             )
      #
      #                             canon_method_node = noko_signed_info_element.at_xpath(
      #                               './ds:CanonicalizationMethod',
      #                               { 'ds' => RubySaml::XML::DSIG }
      #                             )
      #                             canon_algorithm = RubySaml::XML.canon_algorithm(canon_method_node)
      #
      #                             noko_signed_info_element.canonicalize(canon_algorithm)
      #                           end
      # end

      # Get the Reference element
      # @return [Nokogiri::XML::Element, nil] The Reference element
      # def ref
      #   @ref ||= begin
      #              doc = Nokogiri::XML(cached_signed_info)
      #              doc.at_xpath('./ds:Reference', { 'ds' => RubySaml::XML::DSIG })
      #            end
      # end

      # Get the referenced XML that was signed
      # @return [String, nil] The canonicalized referenced XML
      # def referenced_xml
      #   @referenced_xml ||= begin
      #                         return nil if ref.nil?
      #
      #                         hashed_element = find_hashed_element
      #                         return nil if hashed_element.nil?
      #
      #                         canon_algorithm = determine_canonicalization_algorithm
      #                         inclusive_namespaces = extract_inclusive_namespaces
      #
      #                         hashed_element.canonicalize(canon_algorithm, inclusive_namespaces)
      #                       end
      # end

      private

      # Get the certificate element from the document
      # @return [Nokogiri::XML::Element, nil] The certificate element
      def cert_from_response
        @cert_from_response ||= noko.at_xpath(
          '//ds:X509Certificate',
          { 'ds' => RubySaml::XML::DSIG }
        )
      end

      # Extract a certificate from base64 text
      # @param base64_cert [String] The base64-encoded certificate
      # @return [OpenSSL::X509::Certificate] The certificate
      def extract_certificate(base64_cert)
        cert_text = Base64.decode64(base64_cert)
        begin
          OpenSSL::X509::Certificate.new(cert_text)
        rescue OpenSSL::X509::CertificateError => _e
          raise RubySaml::ValidationError.new('Document Certificate Error')
        end
      end

      # Calculate a fingerprint for a certificate
      # @param cert [OpenSSL::X509::Certificate] The certificate
      # @param algorithm_name [String, nil] The algorithm to use
      # @return [String] The fingerprint
      def calculate_fingerprint(cert, algorithm_name = nil)
        if algorithm_name
          fingerprint_alg = RubySaml::XML.hash_algorithm(algorithm_name).new
        else
          fingerprint_alg = OpenSSL::Digest.new('SHA256')
        end
        fingerprint_alg.hexdigest(cert.to_der)
      end

      # Normalize a fingerprint by removing non-alphanumeric characters and converting to lowercase
      # @param fingerprint [String] The fingerprint to normalize
      # @return [String] The normalized fingerprint
      def normalize_fingerprint(fingerprint)
        fingerprint.gsub(/[^a-zA-Z0-9]/, '').downcase
      end

      # Verify that all prerequisites for signature validation are met
      # @raise [RubySaml::ValidationError] If any prerequisite is not met
      # def validate_signature_prerequisites!
      #   raise RubySaml::ValidationError.new('No Signature Hash Algorithm Method found') if signature_hash_algorithm.nil?
      #   raise RubySaml::ValidationError.new('No Signature node found') if signature.nil?
      #   raise RubySaml::ValidationError.new('No canonized SignedInfo') if cached_signed_info.nil?
      #   raise RubySaml::ValidationError.new('No Reference node found') if ref.nil?
      #   raise RubySaml::ValidationError.new('No referenced XML') if referenced_xml.nil?
      # end

      # Verify the digest value matches the calculated digest
      # @raise [RubySaml::ValidationError] If the digest values don't match
      def verify_digest_value
        digest_method_node = Nokogiri::XML(ref.to_s).at_xpath(
          './ds:DigestMethod',
          { 'ds' => RubySaml::XML::DSIG }
        )
        digest_algorithm = RubySaml::XML.hash_algorithm(digest_method_node)
        calculated_digest = digest_algorithm.digest(referenced_xml)

        encoded_digest_value = Nokogiri::XML(ref.to_s).at_xpath(
          './ds:DigestValue',
          { 'ds' => RubySaml::XML::DSIG }
        )
        encoded_digest_value_text = encoded_digest_value&.text&.strip
        actual_digest = encoded_digest_value_text.nil? ? nil : Base64.decode64(encoded_digest_value_text)

        # Compare the computed digest with the signed digest
        unless calculated_digest && calculated_digest == actual_digest
          raise RubySaml::ValidationError.new('Digest mismatch')
        end
      end

      # Verify a signature using a certificate
      # @param cert [OpenSSL::X509::Certificate] The certificate to use
      # @return [Boolean] True if the signature is valid
      def verify_signature_with_cert(cert)
        signature_verified = false
        begin
          signature_verified = cert.public_key.verify(signature_hash_algorithm.new, signature, cached_signed_info)
        rescue OpenSSL::PKey::PKeyError # rubocop:disable Lint/SuppressedException
          # Error is handled by checking signature_verified below
        end
        signature_verified
      end

      # Find the element that was hashed
      # @return [Nokogiri::XML::Element, nil] The hashed element
      def find_hashed_element
        noko_without_sig = noko.clone
        noko_without_sig.at_xpath('//ds:Signature', 'ds' => RubySaml::XML::DSIG)&.remove

        reference_nodes = noko_without_sig.xpath("//*[@ID=$id]", nil, { 'id' => extract_signed_element_id })
        reference_nodes[0]
      end

      # Determine the canonicalization algorithm to use
      # @return [String] The canonicalization algorithm
      # def determine_canonicalization_algorithm
      #   noko_signed_info_element = Nokogiri::XML(cached_signed_info)
      #   canon_method_node = noko_signed_info_element.at_xpath(
      #     './ds:CanonicalizationMethod',
      #     { 'ds' => RubySaml::XML::DSIG }
      #   )
      #   canon_algorithm = RubySaml::XML.canon_algorithm(canon_method_node)
      #   process_transforms(ref, canon_algorithm)
      # end




      # TODO!!!!!!!!
      # Remove the signature element from the document
      signature_node.remove
    end


      # raise RubySaml::ValidationError.new('No Signature Hash Algorithm Method found') if @signature_hash_algorithm.nil?
      #
      # raise RubySaml::ValidationError.new('No Reference node found') if @ref.nil?
      # raise RubySaml::ValidationError.new('No referenced XML') if @referenced_xml.nil?
      # @return [String, nil] The ID of the signed element


    def signature_node
      noko.at_xpath(
        '//ds:Signature',
        { 'ds' => RubySaml::XML::DSIG }
      ) || (raise RubySaml::ValidationError.new('No Signature node found'))
    end

    def signed_info_node
      signature_node.at_xpath('./ds:SignedInfo', 'ds' => RubySaml::XML::DSIG) ||
        (raise RubySaml::ValidationError.new('No SignedInfo node found'))
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


      subject_node = noko.at_xpath("//*[@ID='#{signed_subject_id}']") ||
                     (raise RubySaml::ValidationError.new('No subject node found'))
      subject_node.canonicalize(canon_algorithm, inclusive_namespaces)
    end
      #   canon_algorithm = canon_algorithm_from_transforms || canon_algorithm_from_signed_info
      #   inclusive_namespaces = extract_
      #
      #
      #   return if subject_node.nil?
      #
      #   canon_algorithm = process_transforms(reference_node, canon_algorithm)
      #
      #   [, signature_node]
      #
      #   noko.at_xpath("//*[@ID='#{signed_element_id}"] ||
      #     (raise RubySaml::ValidationError.new('No signed element ID found'))
      #
      #
      # raise RubySaml::ValidationError.new('No canonized SignedInfo') if @cached_signed_info.nil?
      #
      #
      #   canon_algorithm = extract_canon_algorithm(signed_info_node)
      #   signed_info_node = signed_info_node.canonicalize(canon_algorithm)
      #   signed_info_node = Nokogiri::XML(signed_info_node.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)).root
      #
      #
      #   noko.at_xpath(
      #     '//ds:Signature',
      #     { 'ds' => RubySaml::XML::DSIG }
      #   ) || (raise RubySaml::ValidationError.new('No Signature node found'))
      # end

      # Get the ID of the signed element
      # @return [String, nil] The ID of the signed element
      def signed_subject_id
        id = uri_from_reference_node || signature_node.parent['ID']
        return id unless !id || id.empty?
        raise RubySaml::ValidationError.new('No signed element ID found')
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

      private

      def memoize(name)
        name = "@#{name.to_s.delete_prefix('@')}"
        return instance_variable_get(name) if instance_variable_defined?(name)

        instance_variable_set(name, yield)
      end
    end
  end
end

###################################################################













# frozen_string_literal: true
#
# module RubySaml
#   module XML
#     class SignedDocumentInfo
#       extend self
#
#       def extract_body_node(noko, check_malformed_doc: true)
#         unless noko.is_a?(Nokogiri::XML::Document)
#           begin
#             noko = RubySaml::XML.safe_load_nokogiri(document.to_s, check_malformed_doc: check_malformed_doc)
#           rescue StandardError => e
#             raise RubySaml::ValidationError.new("XML load failed: #{e.message}")
#           end
#         end
#
#         signature_node = noko.at_xpath(
#           '//ds:Signature',
#           { 'ds' => RubySaml::XML::DSIG }
#         )
#         return if signature_node.nil?
#
#         signed_info_node = signature_node.at_xpath('./ds:SignedInfo', 'ds' => RubySaml::XML::DSIG)
#         canon_algorithm = extract_canon_algorithm(signed_info_node)
#         signed_info_node = signed_info_node.canonicalize(canon_algorithm)
#         signed_info_node = Nokogiri::XML(signed_info_node.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)).root
#
#         # Remove the signature element from the document
#         signature_node.remove
#
#         # check digests
#         reference_node = signed_info_node.at_xpath('./ds:Reference', { 'ds' => RubySaml::XML::DSIG })
#         return if reference_node.nil?
#
#         signed_element_id = extract_uri(reference_node) || signature_node.parent['ID']
#         body_node = noko.at_xpath("//*[@ID='#{signed_element_id}']")
#         return if body_node.nil?
#
#         canon_algorithm = process_transforms(reference_node, canon_algorithm)
#         inclusive_namespaces = extract_inclusive_namespaces(noko)
#
#         [body_node.canonicalize(canon_algorithm, inclusive_namespaces), signature_node]
#       end
#
#       private
#
#       def extract_canon_algorithm(signed_info_node)
#         canon_method_node = signed_info_node.at_xpath(
#           './ds:CanonicalizationMethod',
#           { 'ds' => RubySaml::XML::DSIG }
#         )
#         RubySaml::XML.canon_algorithm(canon_method_node)
#       end
#
#       def process_transforms(reference_node, canon_algorithm)
#         transforms = reference_node.xpath('./ds:Transforms/ds:Transform', { 'ds' => RubySaml::XML::DSIG })
#
#         # TODO: This should just be a reverse_each
#         transforms.each do |transform_element|
#           algorithm_attr = transform_element['Algorithm']
#           next unless algorithm_attr
#
#           canon_algorithm = RubySaml::XML.canon_algorithm(transform_element, default: false)
#         end
#
#         canon_algorithm
#       end
#
#       # def extract_inclusive_namespaces(doc)
#       #   element = doc.at_xpath(
#       #     '//ec:InclusiveNamespaces',
#       #     { 'ec' => RubySaml::XML::C14N }
#       #   )
#       #   return unless element
#       #
#       #   element['PrefixList']&.split
#       # end
#
#       def extract_uri(reference_node)
#         uri = reference_node&.[]('URI')
#         return nil unless uri
#
#         uri = uri[1..] if uri.start_with?('#')
#         uri unless uri.empty?
#       end
#     end
#   end
# end
#
#
#
# # frozen_string_literal: true
#
# module RubySaml
#   module XML
#     module ReferencedNodeExtractor
#       extend self
#
#       def extract_body_node(noko, check_malformed_doc: true)
#         unless noko.is_a?(Nokogiri::XML::Document)
#           begin
#             noko = RubySaml::XML.safe_load_nokogiri(document.to_s, check_malformed_doc: check_malformed_doc)
#           rescue StandardError => e
#             raise RubySaml::ValidationError.new("XML load failed: #{e.message}")
#           end
#         end
#
#
#       private
#
#       # def extract_inclusive_namespaces(doc)
#       #   element = doc.at_xpath(
#       #     '//ec:InclusiveNamespaces',
#       #     { 'ec' => RubySaml::XML::C14N }
#       #   )
#       #   return unless element
#       #
#       #   element['PrefixList']&.split
#       # end
#       #
#       # def extract_uri(reference_node)
#       #   uri = reference_node&.[]('URI')
#       #   return nil unless uri
#       #
#       #   uri = uri[1..] if uri.start_with?('#')
#       #   uri unless uri.empty?
#       # end
#     end
#   end
# end
