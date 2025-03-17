# frozen_string_literal: true

module RubySaml
  module Idp
    module Validators
      # Validator class for SAML Responses
      class ResponseValidator
        include XMLProcessing
        include Validation

        attr_reader :response, :document, :settings, :options, :errors, :soft, :assertion

        # Initialize the validator with a response object and its related data
        def initialize(response, document, decrypted_document, assertion, settings, options = {})
          @response = response
          @document = document
          @decrypted_document = decrypted_document
          @assertion = assertion
          @settings = settings
          @options = options
          @errors = []
          @soft = settings&.soft.nil? ? true : settings.soft
        end

        # Validate the response
        def validate(collect_errors = false)
          run_validations(validation_methods, collect_errors)
        end

        # Append an error message
        def append_error(error_msg, soft_mode = nil)
          soft_mode = @soft if soft_mode.nil?
          @errors << error_msg
          raise ValidationError.new(error_msg) unless soft_mode
          false
        end

        # Reset the errors array
        def reset_errors!
          @errors = []
        end

        private

        # List of validations to perform
        def validation_methods
          %i[
            validate_response_state
            validate_version
            validate_id
            validate_success_status
            validate_num_assertion
            validate_signed_elements
            validate_structure
            validate_no_duplicated_attributes
            validate_in_response_to
            validate_conditions
            validate_audience
            validate_destination
            validate_issuer
            validate_session_expiration
            validate_subject_confirmation
            validate_name_id
            validate_signature
          ]
        end

        # Validate the response state
        def validate_response_state
          return append_error("Blank response", soft) if response.nil? || response.empty?
          return append_error("No settings provided", soft) if settings.nil?

          if settings.idp_cert_fingerprint.nil? &&
            settings.idp_cert.nil? &&
            settings.idp_cert_multi.nil?
            return append_error("No fingerprint or certificate provided", soft)
          end

          true
        end

        # Validate the Success status
        def validate_success_status
          status_code = @response.status_code
          status_message = @response.status_message
          return true if status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"

          error_msg = "Status code was not Success"
          status_error_msg = RubySaml::Utils.status_error_msg(error_msg, status_code, status_message)
          append_error(status_error_msg, soft)
        end

        # Validate that there is only one assertion
        def validate_num_assertion
          error_msg = "SAML Response must contain 1 assertion"
          assertions = xpath_extract(document, "//a:Assertion")
          encrypted_assertions = xpath_extract(document, "//a:EncryptedAssertion")

          unless assertions.size + encrypted_assertions.size == 1
            return append_error(error_msg, soft)
          end

          unless @decrypted_document.nil?
            assertions = xpath_extract(@decrypted_document, "//a:Assertion")
            unless assertions.size == 1
              return append_error(error_msg, soft)
            end
          end

          true
        end

        # Validate the signed elements
        def validate_signed_elements
          signature_nodes = (@decrypted_document || document).xpath(
            "//ds:Signature", { "ds" => RubySaml::XML::DSIG }
          )
          signed_elements = []
          verified_seis = []
          verified_ids = []

          signature_nodes.each do |signature_node|
            signed_element = signature_node.parent.name
            if signed_element != 'Response' && signed_element != 'Assertion'
              return append_error(
                "Invalid Signature Element '#{signed_element}'. SAML Response rejected",
                soft
              )
            end

            if signature_node.parent['ID'].nil?
              return append_error("Signed Element must contain an ID. SAML Response rejected", soft)
            end

            id = signature_node.parent['ID']
            if verified_ids.include?(id)
              return append_error("Duplicated ID. SAML Response rejected", soft)
            end
            verified_ids.push(id)

            # Check reference URI matches parent ID and no duplicate References or IDs
            ref = signature_node.at_xpath(".//ds:Reference", { "ds" => RubySaml::XML::DSIG })
            if ref
              uri = ref['URI']
              if uri && !uri.empty?
                sei = uri[1..]

                unless sei == id
                  return append_error("Found an invalid Signed Element. SAML Response rejected", soft)
                end

                if verified_seis.include?(sei)
                  return append_error("Duplicated Reference URI. SAML Response rejected", soft)
                end

                verified_seis.push(sei)
              end
            end

            signed_elements << signed_element
          end

          unless signature_nodes.size < 3 && !signed_elements.empty?
            return append_error(
              "Found an unexpected number of Signature Elements. SAML Response rejected",
              soft
            )
          end

          if settings.security[:want_assertions_signed] && !(signed_elements.include? "Assertion")
            return append_error(
              "The Assertion of the Response is not signed and the SP requires it",
              soft
            )
          end

          true
        end

        # Validate the attributes
        def validate_no_duplicated_attributes
          if options[:check_duplicated_attributes]
            begin
              @response.attributes
            rescue ValidationError => e
              return append_error(e.message, soft)
            end
          end

          true
        end

        # Validate InResponseTo
        def validate_in_response_to
          in_response_to = @response.in_response_to
          return true unless options.key? :matches_request_id
          return true if options[:matches_request_id].nil?
          return true unless options[:matches_request_id] != in_response_to

          error_msg = "InResponseTo #{in_response_to} does not match request ID #{options[:matches_request_id]}"
          append_error(error_msg, soft)
        end

        # Validate conditions
        def validate_conditions
          # One conditions element
          return true if options[:skip_conditions]

          conditions_nodes = @response.signed_assertion.xpath(
            "./a:Conditions", SAML_NAMESPACES
          )

          unless conditions_nodes.size == 1
            return append_error("The Assertion must include one Conditions element", soft)
          end

          # Validate AuthnStatement
          return true if options[:skip_authnstatement]

          authnstatement_nodes = @response.signed_assertion.xpath(
            "./a:AuthnStatement", SAML_NAMESPACES
          )

          unless authnstatement_nodes.size == 1
            return append_error("The Assertion must include one AuthnStatement element", soft)
          end

          # Time window validation
          conditions = @response.conditions
          return true if conditions.nil?
          return true if options[:skip_conditions]

          if @response.not_before
            validate_time_condition(
              @response.not_before, "NotBefore", :before, allowed_clock_drift
            )
          end

          if @response.not_on_or_after
            validate_time_condition(
              @response.not_on_or_after, "NotOnOrAfter", :after, allowed_clock_drift
            )
          end

          true
        end

        # Validate the audience
        def validate_audience
          return true if options[:skip_audience]
          return true if settings.sp_entity_id.nil? || settings.sp_entity_id.empty?

          audiences = @response.audiences

          if audiences.empty?
            return true unless settings.security[:strict_audience_validation]
            return append_error(
              "Invalid Audiences. The <AudienceRestriction> element contained only empty <Audience> elements.",
              soft
            )
          end

          unless audiences.include? settings.sp_entity_id
            s = audiences.count > 1 ? 's' : ''
            error_msg = "Invalid Audience#{s}. The audience#{s} #{audiences.join(',')} " +
              "did not match the expected audience #{settings.sp_entity_id}"
            return append_error(error_msg, soft)
          end

          true
        end

        # Validate the destination
        def validate_destination
          destination = @response.destination
          return true if destination.nil?
          return true if options[:skip_destination]

          if destination.empty?
            return append_error("The response has an empty Destination value", soft)
          end

          return true if settings.assertion_consumer_service_url.nil? ||
            settings.assertion_consumer_service_url.empty?

          unless RubySaml::Utils.uri_match?(destination, settings.assertion_consumer_service_url)
            error_msg = "The response was received at #{destination} instead of #{settings.assertion_consumer_service_url}"
            return append_error(error_msg, soft)
          end

          true
        end

        # Validate the issuer
        def validate_issuer
          return true if settings.idp_entity_id.nil?

          begin
            obtained_issuers = @response.issuers
          rescue ValidationError => e
            return append_error(e.message, soft)
          end

          obtained_issuers.each do |issuer_value|
            unless RubySaml::Utils.uri_match?(issuer_value, settings.idp_entity_id)
              error_msg = "Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer_value}>"
              return append_error(error_msg, soft)
            end
          end

          true
        end

        # Validate the session expiration
        def validate_session_expiration
          session_expires_at = @response.session_expires_at
          return true if session_expires_at.nil?

          validate_time_condition(
            session_expires_at, "SessionNotOnOrAfter", :after, allowed_clock_drift
          )
        end

        # Validate the subject confirmation
        def validate_subject_confirmation
          return true if options[:skip_subject_confirmation]
          valid_subject_confirmation = false

          subject_confirmation_nodes = @response.signed_assertion.xpath(
            "./a:Subject/a:SubjectConfirmation", SAML_NAMESPACES
          )

          now = Time.now.utc
          subject_confirmation_nodes.each do |subject_confirmation|
            if subject_confirmation['Method'] != 'urn:oasis:names:tc:SAML:2.0:cm:bearer'
              next
            end

            confirmation_data_node = subject_confirmation.at_xpath(
              'a:SubjectConfirmationData',
              { "a" => RubySaml::XML::NS_ASSERTION }
            )

            next unless confirmation_data_node

            next if (confirmation_data_node['InResponseTo'] &&
              confirmation_data_node['InResponseTo'] != @response.in_response_to) ||
              (confirmation_data_node['NotBefore'] &&
                now < (parse_time(confirmation_data_node, "NotBefore") - allowed_clock_drift)) ||
              (confirmation_data_node['NotOnOrAfter'] &&
                now >= (parse_time(confirmation_data_node, "NotOnOrAfter") + allowed_clock_drift)) ||
              (confirmation_data_node['Recipient'] &&
                !options[:skip_recipient_check] &&
                settings &&
                confirmation_data_node['Recipient'] != settings.assertion_consumer_service_url)

            valid_subject_confirmation = true
            break
          end

          unless valid_subject_confirmation
            return append_error("A valid SubjectConfirmation was not found on this Response", soft)
          end

          true
        end

        # Validate the name ID
        def validate_name_id
          if assertion.nil? || assertion.name_id_node.nil?
            if settings.security[:want_name_id]
              return append_error("No NameID element found in the assertion", soft)
            end
          else
            if assertion.name_id.nil? || assertion.name_id.empty?
              return append_error("An empty NameID value found", soft)
            end

            if !(settings.sp_entity_id.nil? ||
              settings.sp_entity_id.empty? ||
              assertion.name_id_spnamequalifier.nil? ||
              assertion.name_id_spnamequalifier.empty?) &&
              (assertion.name_id_spnamequalifier != settings.sp_entity_id)
              return append_error('SPNameQualifier value does not match the SP entityID', soft)
            end
          end

          true
        end

        # Validate the signature
        def validate_signature
          doc = @response.doc_to_validate

          subject_id = RubySaml::XML::SignedDocumentValidator.subject_id(document)
          sig_elements = []
          if subject_id
            sig_elements = document.xpath(
              "/p:Response[@ID=$id]/ds:Signature",
              { "p" => RubySaml::XML::NS_PROTOCOL, "ds" => RubySaml::XML::DSIG },
              id: subject_id
            )
          end

          # Check signature node inside assertion
          if sig_elements.empty?
            subject_id = RubySaml::XML::SignedDocumentValidator.subject_id(doc)
            sig_elements = doc.xpath(
              "/p:Response/a:Assertion[@ID=$id]/ds:Signature",
              SAML_NAMESPACES,
              id: subject_id
            )
          end

          if sig_elements.size != 1
            if sig_elements.empty?
              append_error("Signed element ID #{subject_id} is not found", soft)
            else
              append_error("Signed element ID #{subject_id} is found more than once", soft)
            end
            return append_error("Invalid Signature on SAML Response", soft)
          end

          idp_certs = settings.get_idp_cert_multi
          idp_cert = settings.get_idp_cert
          fingerprint = settings.get_fingerprint
          check_expiration = settings.security[:check_idp_cert_expiration]

          # Validate with appropriate certificates
          valid = validate_signature(
            doc,
            idp_certs,
            idp_cert,
            fingerprint,
            check_expiration: check_expiration
          )

          unless valid
            return append_error("Invalid Signature on SAML Response", soft)
          end

          true
        end
      end
    end
  end
end
