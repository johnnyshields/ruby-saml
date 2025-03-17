# frozen_string_literal: true

module RubySaml
  module Messages
    # Base builder for SP-initiated SAML messages
    class MessageBuilder < Message
      include XMLProcessing

      attr_accessor :uuid

      # Generate a signed XML document
      def build_message(settings, root_name, attributes, security_option, &block)
        document = create_xml_document(root_name, attributes, &block)
        sign_document(document, settings, security_option)
      end

      # Create URL parameters including signatures if needed
      def build_params(settings, xml_doc, relay_state, param_name, security_option, binding_type)
        binding_redirect = binding_type == Utils::BINDINGS[:redirect]
        create_params(settings, xml_doc, binding_redirect, relay_state, security_option, param_name)
      end

      # Build the final URL
      def build_url(settings, params, service_url, param_name)
        create_url(settings, params, service_url, param_name)
      end

      # Get the service URL from settings based on type
      def service_url(settings, type)
        case type
        when :sso then settings.idp_sso_service_url
        when :slo then settings.idp_slo_service_url
        when :slo_response then settings.idp_slo_response_service_url || settings.idp_slo_service_url
        else nil
        end
      end

      # Create URL with SAML parameters
      def create_url(settings, params, service_url, param_name)
        raise ValidationError.new("Service URL cannot be nil") if service_url.nil? || service_url.empty?

        params_prefix = /\?/.match?(service_url) ? '&' : '?'
        param_value = CGI.escape(params.delete(param_name))
        url_params = +"#{params_prefix}#{param_name}=#{param_value}"

        params.each_pair do |key, value|
          url_params << "&#{key}=#{CGI.escape(value.to_s)}"
        end

        service_url + url_params
      end

      # Process relay state from params
      def process_relay_state(params)
        relay_state = params[:RelayState] || params['RelayState']

        if relay_state.nil?
          params.delete(:RelayState)
          params.delete('RelayState')
        end

        relay_state
      end

      # Build signature parameters
      def build_signature_params(settings, base64_data, relay_state, binding_redirect, security_option)
        params = {}
        sp_signing_key = settings.get_sp_signing_key

        if binding_redirect && settings.security[security_option] && sp_signing_key
          params['SigAlg'] = settings.get_sp_signature_method
          url_string = RubySaml::Utils.build_query(
            type: @request_type,
            data: base64_data,
            relay_state: relay_state,
            sig_alg: params['SigAlg']
          )
          sign_algorithm = RubySaml::XML.hash_algorithm(settings.get_sp_signature_method)
          signature = sp_signing_key.sign(sign_algorithm.new, url_string)
          params['Signature'] = Base64.strict_encode64(signature)
        end

        params
      end

      # Create parameters for SAML request/response
      def create_params(settings, xml_doc, binding_redirect, relay_state, security_option, param_name)
        request_doc = xml_doc
        message = request_doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)

        Logging.debug "Created #{param_name}: #{message}"

        @request_type = param_name
        base64_message = RubySaml::XML::Decoder.encode_message(message, compress: binding_redirect)
        message_params = { param_name => base64_message }

        signature_params = build_signature_params(
          settings,
          base64_message,
          relay_state,
          binding_redirect,
          security_option
        )

        params = {}
        params.merge!(signature_params)

        params.each_pair do |key, value|
          message_params[key] = value.to_s
        end

        message_params
      end

      # Determine the binding type from settings
      def binding_type(settings, type = :service)
        case type
        when :sso then settings.idp_sso_service_binding
        when :slo then settings.idp_slo_service_binding
        else nil
        end
      end

      # Generate a UUID
      def generate_uuid(settings)
        RubySaml::Utils.generate_uuid(settings.sp_uuid_prefix)
      end
    end
  end
end

# frozen_string_literal: true

module RubySaml
  module Messages
    module RequestBuilding
    end
  end
end