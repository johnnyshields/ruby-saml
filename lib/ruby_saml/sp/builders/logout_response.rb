# frozen_string_literal: true

module RubySaml
  module Sp
    module Builders
      # SAML LogoutResponse builder (SLO, IdP-initiated)
      class LogoutResponse < MessageBuilder
        alias_method :response_id, :uuid

        # Create the LogoutResponse
        def create(settings, request_id = nil, logout_message = nil, params = {}, status_code = nil)
          @uuid = generate_uuid(settings)
          relay_state = process_relay_state(params)

          service_url = service_url(settings, :slo_response)
          raise SettingsError.new("Missing IdP SLO service URL") if service_url.nil? || service_url.empty?

          xml_doc = create_logout_response_xml(settings, request_id, logout_message, status_code)

          binding = binding_type(settings, :slo)
          response_params = build_params(
            settings, xml_doc, relay_state, "SAMLResponse", :logout_responses_signed, binding
          )

          @logout_url = build_url(settings, response_params, service_url, "SAMLResponse")
        end

        private

        # Build the XML document
        def create_logout_response_xml(settings, request_id = nil, status_message = nil, status_code = nil)
          time = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')

          # Default values if not provided
          status_code ||= 'urn:oasis:names:tc:SAML:2.0:status:Success'
          status_message ||= 'Successfully Signed Out'

          root_attributes = {
            'xmlns:samlp' => RubySaml::XML::NS_PROTOCOL,
            'xmlns:saml' => RubySaml::XML::NS_ASSERTION,
            'ID' => uuid,
            'IssueInstant' => time,
            'Version' => '2.0',
            'InResponseTo' => request_id,
            'Destination' => service_url(settings, :slo_response)
          }

          build_message(settings, 'LogoutResponse', root_attributes, :logout_responses_signed) do |xml|
            # Add Issuer
            xml['saml'].Issuer(settings.sp_entity_id) if settings.sp_entity_id

            # Add Status
            xml['samlp'].Status do
              xml['samlp'].StatusCode(Value: status_code)
              xml['samlp'].StatusMessage(status_message)
            end
          end
        end
      end
    end
  end
end
