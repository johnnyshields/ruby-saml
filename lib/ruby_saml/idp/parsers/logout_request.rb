# frozen_string_literal: true

module RubySaml
  module Idp
    module Parsers
      # SAML Logout Request parser
      class LogoutRequest < MessageParser
        # Initialize a LogoutRequest
        def initialize(request, options = {})
          super()
          raise ArgumentError.new("Request cannot be nil") if request.nil?
          init_parser(request, options)
        end

        # Check if the request is valid
        def is_valid?(collect_errors = false)
          run_validations(validation_methods, collect_errors)
        end

        # Get the request ID
        def request_id
          extract_from_document(document, "/p:LogoutRequest", 'ID')
        end

        # Get the NameID from the request
        def name_id
          @name_id ||= name_id_node&.text
        end
        alias_method :nameid, :name_id

        # Get the NameID Format
        def name_id_format
          @name_id_format ||= name_id_node&.[]('Format')
        end
        alias_method :nameid_format, :name_id_format

        # Get the NameID node
        def name_id_node
          @name_id_node ||= begin
                              encrypted_node = xpath_first(document,
                                                           "/p:LogoutRequest/a:EncryptedID"
                              )
                              if encrypted_node
                                RubySaml::XML::Decryptor.decrypt_nameid(encrypted_node, settings&.get_sp_decryption_keys)
                              else
                                xpath_first(document, "/p:LogoutRequest/a:NameID")
                              end
                            end
        end

        # Get the Issuer
        def issuer
          @issuer ||= extract_from_document(document, "/p:LogoutRequest/a:Issuer")
        end

        # Get the NotOnOrAfter attribute
        def not_on_or_after
          @not_on_or_after ||= begin
                                 node = xpath_first(document, "/p:LogoutRequest")

                                 if (value = node&.attributes&.[]("NotOnOrAfter"))
                                   Time.parse(value)
                                 end
                               end
        end

        # Get the SessionIndex values
        def session_indexes
          xpath_extract(document, "/p:LogoutRequest/p:SessionIndex").map(&:text)
        end

        private

        # List of validations to perform
        def validation_methods
          %i[
            validate_message_state
            validate_id
            validate_version
            validate_structure
            validate_not_on_or_after
            validate_issuer
            validate_signature
          ]
        end

        # Validate the request state
        def validate_message_state
          validate_message_state("LogoutRequest")
        end

        # Validate the NotOnOrAfter time
        def validate_not_on_or_after
          return true if not_on_or_after.nil?

          validate_time_condition(not_on_or_after, "NotOnOrAfter", :after, allowed_clock_drift)
        end

        # Validate the Issuer
        def validate_issuer
          return true if settings.nil? || settings.idp_entity_id.nil? || issuer.nil?

          validate_issuer(issuer, settings.idp_entity_id)
        end

        # Validate the Signature
        def validate_signature
          validate_redirect_signature("SAMLRequest")
        end
      end
    end
  end
end
