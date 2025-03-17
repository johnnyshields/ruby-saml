# frozen_string_literal: true

module RubySaml
  module Idp
    module Parsers
      # SAML Logout Response parser
      class LogoutResponse < MessageParser
        # Initialize a LogoutResponse
        def initialize(response, settings = nil, options = {})
          super()
          raise ArgumentError.new("Response cannot be nil") if response.nil?

          init_parser(response, options)
          @settings = settings
          @soft = settings&.soft.nil? ? true : settings.soft
        end

        # Get the response ID
        def response_id
          extract_from_document(document, "/p:LogoutResponse", 'ID')
        end

        # Check if the status is successful
        def success?
          status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
        end

        # Get the InResponseTo attribute
        def in_response_to
          @in_response_to ||= extract_from_document(document, "/p:LogoutResponse", 'InResponseTo')
        end

        # Get the Issuer
        def issuer
          @issuer ||= extract_from_document(document, "/p:LogoutResponse/a:Issuer")
        end

        # Get the StatusCode
        def status_code
          @status_code ||= extract_from_document(document,
                                                 "/p:LogoutResponse/p:Status/p:StatusCode", 'Value'
          )
        end

        # Get the StatusMessage
        def status_message
          @status_message ||= extract_from_document(document,
                                                    "/p:LogoutResponse/p:Status/p:StatusMessage"
          )
        end

        # Check if the response is valid
        def validate(collect_errors = false)
          run_validations(validation_methods, collect_errors)
        end

        private

        # List of validations to perform
        def validation_methods
          %i[
            validate_state
            validate_success_status
            validate_structure
            validate_in_response_to
            validate_issuer
            validate_signature
          ]
        end

        # Validate the response state
        def validate_state
          return append_error("Blank logout response", soft) if @message.empty?
          return append_error("No settings provided", soft) if settings.nil?
          return append_error("No SP entity ID in settings", soft) if settings.sp_entity_id.nil?

          validate_certificate_presence
        end

        # Validate the Success status
        def validate_success_status
          validate_success_status(status_code, status_message)
        end

        # Validate the InResponseTo matches the request ID
        def validate_in_response_to
          return true unless options.key? :matches_request_id
          return true if options[:matches_request_id].nil?
          return true unless options[:matches_request_id] != in_response_to

          error_msg = "InResponseTo #{in_response_to} does not match request ID #{options[:matches_request_id]}"
          append_error(error_msg, soft)
        end

        # Validate the Issuer
        def validate_issuer
          return true if settings.idp_entity_id.nil? || issuer.nil?

          validate_issuer(issuer, settings.idp_entity_id)
        end

        # Validate the Signature
        def validate_signature
          validate_redirect_signature("SAMLResponse")
        end
      end
    end
  end
end
