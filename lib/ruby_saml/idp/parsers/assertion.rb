# frozen_string_literal: true

module RubySaml
  module Idp
    module Parsers
      # SAML Assertion parser
      class Assertion < Message
        include XMLProcessing

        attr_reader :document, :settings

        # Initialize with a Nokogiri document representing an Assertion
        def initialize(document, settings = nil)
          super()
          @document = document
          @settings = settings
        end

        # Get the assertion ID
        def id
          @id ||= document['ID']
        end

        # Get the name ID
        def name_id
          @name_id ||= name_id_node&.text
        end

        # Get the name ID format
        def name_id_format
          @name_id_format ||= name_id_node&.[]('Format')
        end

        # Get the name ID SPNameQualifier
        def name_id_spnamequalifier
          @name_id_spnamequalifier ||= name_id_node&.[]('SPNameQualifier')
        end

        # Get the name ID NameQualifier
        def name_id_namequalifier
          @name_id_namequalifier ||= name_id_node&.[]('NameQualifier')
        end

        # Get the subject node
        def subject
          @subject ||= xpath_first(document, "./a:Subject")
        end

        # Get the name ID node
        def name_id_node
          @name_id_node ||= begin
                              return nil unless subject
                              encrypted_node = xpath_first(subject, "./a:EncryptedID")
                              if encrypted_node
                                RubySaml::XML::Decryptor.decrypt_nameid(
                                  encrypted_node, settings&.get_sp_decryption_keys
                                )
                              else
                                xpath_first(subject, "./a:NameID")
                              end
                            end
        end

        # Get the conditions element
        def conditions
          @conditions ||= xpath_first(document, "./a:Conditions")
        end

        # Get the NotBefore value
        def not_before
          @not_before ||= parse_time(conditions, "NotBefore")
        end

        # Get the NotOnOrAfter value
        def not_on_or_after
          @not_on_or_after ||= parse_time(conditions, "NotOnOrAfter")
        end

        # Get the Issuer
        def issuer
          @issuer ||= xpath_first(document, "./a:Issuer")&.text
        end

        # Get the audiences
        def audiences
          @audiences ||= xpath_extract(
            document, "./a:Conditions/a:AudienceRestriction/a:Audience"
          ).map(&:text).reject(&:empty?)
        end

        # Get the authentication statement
        def authn_statement
          @authn_statement ||= xpath_first(document, "./a:AuthnStatement")
        end

        # Get the authentication context class reference
        def authn_context_class_ref
          @authn_context_class_ref ||= xpath_first(
            document, "./a:AuthnStatement/a:AuthnContext/a:AuthnContextClassRef"
          )&.text
        end

        # Get the session expiration time
        def session_expires_at
          @session_expires_at ||= parse_time(authn_statement, "SessionNotOnOrAfter")
        end

        # Get the authentication instant
        def authn_instant
          @authn_instant ||= authn_statement&.[]('AuthnInstant')
        end

        # Get the session index
        def session_index
          @session_index ||= authn_statement&.[]('SessionIndex')
        end

        # Get the attribute statement
        def attribute_statement
          @attribute_statement ||= xpath_first(document, "./a:AttributeStatement")
        end

        # Get all attributes
        def attributes
          @attributes ||= begin
                            result = {}

                            return result unless attribute_statement

                            attribute_nodes = xpath_extract(attribute_statement, "./a:Attribute")
                            attribute_nodes.each do |node|
                              name = node['Name']
                              values = node.xpath("./a:AttributeValue", {"a" => RubySaml::XML::NS_ASSERTION}).map(&:text)
                              result[name] = values.size == 1 ? values.first : values
                            end

                            result
                          end
        end

        # Process all encrypted attributes
        def process_encrypted_attributes
          return unless attribute_statement

          encrypted_attribute_nodes = xpath_extract(attribute_statement, "./a:EncryptedAttribute")
          encrypted_attribute_nodes.each do |node|
            decrypted_node = RubySaml::XML::Decryptor.decrypt_attribute(
              node, settings&.get_sp_decryption_keys
            )

            name = decrypted_node['Name']
            values = decrypted_node.xpath(
              "./a:AttributeValue",
              {"a" => RubySaml::XML::NS_ASSERTION}
            ).map(&:text)

            @attributes ||= {}
            @attributes[name] = values.size == 1 ? values.first : values
          end
        end

        # Get all subject confirmation nodes
        def subject_confirmations
          return [] unless subject
          xpath_extract(subject, "./a:SubjectConfirmation")
        end

        # Get bearer subject confirmation data
        def bearer_confirmation_data
          bearer_confirmations = subject_confirmations.select do |confirmation|
            confirmation['Method'] == 'urn:oasis:names:tc:SAML:2.0:cm:bearer'
          end

          return nil if bearer_confirmations.empty?

          bearer_confirmations.map do |confirmation|
            confirmation.at_xpath(
              './a:SubjectConfirmationData',
              { "a" => RubySaml::XML::NS_ASSERTION }
            )
          end.compact.first
        end

        # Get recipient from bearer confirmation data
        def recipient
          data = bearer_confirmation_data
          data && data['Recipient']
        end

        # Get InResponseTo from bearer confirmation data
        def in_response_to
          data = bearer_confirmation_data
          data && data['InResponseTo']
        end
      end
    end
  end
end
