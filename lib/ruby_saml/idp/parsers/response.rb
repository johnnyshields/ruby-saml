# frozen_string_literal: true

module RubySaml
  module Idp
    module Parsers
      # SAML Response with Assertion parser
      class Response < MessageParser
        attr_reader :document, :decrypted_document, :errors

        # Initialize a Response
        def initialize(response, options = {})
          super()
          raise ArgumentError.new("Response cannot be nil") if response.nil?

          @errors = []
          @options = options
          @soft = true

          if options[:settings]
            @settings = options[:settings]
            @soft = @settings.soft unless @settings.soft.nil?
          end

          @response = RubySaml::XML::Decoder.decode_message(response, @settings&.message_max_bytesize)
          @document = RubySaml::XML.safe_load_nokogiri(@response)

          if assertion_encrypted?
            @decrypted_document = generate_decrypted_document
          end
        end

        # Create validator for this response
        def validator
          @validator ||= ResponseValidator.new(
            @response, document, decrypted_document, assertion, @settings, @options
          )
        end

        # Check if the response is valid
        def is_valid?(collect_errors = false)
          result = validator.validate(collect_errors)
          @errors = validator.errors
          result
        end

        # Get the assertion object
        def assertion
          @assertion ||= begin
                           assertion_node = signed_assertion
                           if assertion_node.nil? || assertion_node.root?
                             nil
                           else
                             Assertion.new(assertion_node, @settings)
                           end
                         end
        end

        # Get the NameID from the response via the assertion
        def name_id
          assertion&.name_id
        end
        alias_method :nameid, :name_id

        # Get the NameID Format via the assertion
        def name_id_format
          assertion&.name_id_format
        end
        alias_method :nameid_format, :name_id_format

        # Get the NameID SPNameQualifier via the assertion
        def name_id_spnamequalifier
          assertion&.name_id_spnamequalifier
        end

        # Get the NameID NameQualifier via the assertion
        def name_id_namequalifier
          assertion&.name_id_namequalifier
        end

        # Get the SessionIndex via the assertion
        def sessionindex
          assertion&.session_index
        end

        # Get the attributes via the assertion
        def attributes
          @attr_statements ||= begin
                                 attributes = Attributes.new

                                 assertion&.attributes&.each do |name, values|
                                   attributes.add(name, Array(values))
                                 end

                                 attributes
                               end
        end

        # Get the session expiration time via the assertion
        def session_expires_at
          assertion&.session_expires_at
        end

        # Get the authentication instant via the assertion
        def authn_instant
          assertion&.authn_instant
        end

        # Get the authentication context class reference via the assertion
        def authn_context_class_ref
          assertion&.authn_context_class_ref
        end

        # Check if the status code is Success
        def success?
          status_code == 'urn:oasis:names:tc:SAML:2.0:status:Success'
        end

        # Get the status code
        def status_code
          @status_code ||= begin
                             nodes = xpath_extract(document, "/p:Response/p:Status/p:StatusCode")
                             if nodes.size == 1
                               node = nodes[0]
                               code = node['Value'] if node

                               unless code == "urn:oasis:names:tc:SAML:2.0:status:Success"
                                 inner_nodes = xpath_extract(
                                   document, "/p:Response/p:Status/p:StatusCode/p:StatusCode"
                                 )
                                 statuses = inner_nodes.map { |inner_node| inner_node['Value'] }

                                 code = [code, statuses].flatten.join(" | ")
                               end

                               code
                             end
                           end
        end

        # Get the status message
        def status_message
          @status_message ||= extract_from_document(
            document, "/p:Response/p:Status/p:StatusMessage"
          )
        end

        # Get the conditions element via the assertion
        def conditions
          assertion&.conditions
        end

        # Get the NotBefore value via the assertion
        def not_before
          assertion&.not_before
        end

        # Get the NotOnOrAfter value via the assertion
        def not_on_or_after
          assertion&.not_on_or_after
        end

        # Get the issuers (from Response and Assertion)
        def issuers
          @issuers ||= begin
                         issuer_response_nodes = xpath_extract(document, "/p:Response/a:Issuer")

                         unless issuer_response_nodes.size == 1
                           error_msg = "Issuer of the Response not found or multiple."
                           raise ValidationError.new(error_msg)
                         end

                         response_issuer = issuer_response_nodes.first.text
                         assertion_issuer = assertion&.issuer

                         issuer_values = [response_issuer]
                         issuer_values << assertion_issuer if assertion_issuer

                         issuer_values.reject(&:empty?).uniq
                       end
        end

        # Get the InResponseTo attribute from the Response
        def in_response_to
          @in_response_to ||= extract_from_document(document, "/p:Response", 'InResponseTo')
        end

        # Get the destination
        def destination
          @destination ||= extract_from_document(document, "/p:Response", 'Destination')
        end

        # Get the audiences via the assertion
        def audiences
          assertion&.audiences || []
        end

        # Check if the assertion is encrypted
        def assertion_encrypted?
          !!xpath_first(document,
                        "/p:Response/EncryptedAssertion | /p:Response/a:EncryptedAssertion"
          )
        end

        # Get the response ID
        def response_id
          extract_from_document(document, "/p:Response", 'ID')
        end

        # Get the assertion ID via the assertion
        def assertion_id
          assertion&.id
        end

        # Get the name ID node via the assertion
        def name_id_node
          assertion&.name_id_node
        end

        # Get the document to validate for signatures
        def doc_to_validate
          subject_id = RubySaml::XML::SignedDocumentValidator.subject_id(document)
          return decrypted_document unless subject_id

          sig_elements = document.xpath(
            "/p:Response[@ID=$id]/ds:Signature",
            { "p" => RubySaml::XML::NS_PROTOCOL, "ds" => RubySaml::XML::DSIG },
            id: subject_id
          )

          use_original = sig_elements.size == 1 || decrypted_document.nil?
          use_original ? document : decrypted_document
        end

        # Allow validator to access signed_assertion (used in validation)
        def signed_assertion
          @signed_assertion ||= cached_signed_assertion
        end

        private

        # Get the cached signed assertion
        def cached_signed_assertion
          empty_doc = Nokogiri::XML::Document.new

          xml = doc_to_validate
          return empty_doc if xml.nil?

          subject = RubySaml::XML::SignedDocumentValidator.subject_node(xml)
          return empty_doc if xml.nil? # when no signature/reference is found, return empty document

          subject_id = RubySaml::XML::SignedDocumentValidator.subject_id(xml)
          return nil unless subject_id

          if subject['ID'] != subject_id
            return empty_doc
          end

          assertion = empty_doc
          if subject.name == "Response"
            if (result = subject.at_xpath("a:Assertion", {"a" => RubySaml::XML::NS_ASSERTION}))
              assertion = result
            elsif (result = subject.at_xpath("a:EncryptedAssertion", {"a" => RubySaml::XML::NS_ASSERTION}))
              assertion = RubySaml::XML::Decryptor.decrypt_assertion(result, @settings&.get_sp_decryption_keys)
            end
          elsif subject.name == "Assertion"
            assertion = subject
          end

          assertion
        end

        # Extract the first matching element from the signed assertion
        def xpath_first_from_signed_assertion(subpath = nil)
          return if !subpath || subpath.empty?
          signed_assertion.at_xpath("./#{subpath}", SAML_NAMESPACES)
        end

        # Extract all matching elements from the signed assertion
        def xpath_from_signed_assertion(subpath = nil)
          return if !subpath || subpath.empty?
          signed_assertion.xpath("./#{subpath}", SAML_NAMESPACES)
        end

        # Generate the decrypted document
        def generate_decrypted_document
          RubySaml::XML::Decryptor.decrypt_document(document, @settings&.get_sp_decryption_keys)
        end
      end
    end
  end
end
