# frozen_string_literal: true

module RubySaml
module Messages
module Idp
  class MessageParser

    attr_accessor :errors

    # Append the cause to the errors array, and based on the value of soft, return false or raise
    # an exception. soft_override is provided as a means of overriding the object's notion of
    # soft for just this invocation.
    def append_error(error_msg, soft_override = false) # rubocop:disable Style/OptionalBooleanParameter
      @errors << error_msg

      unless soft_override || (respond_to?(:soft) && soft)
        raise ValidationError.new(error_msg)
      end

      false
    end

    # Reset the errors array
    def reset_errors!
      @errors = []
    end

    # @return [Nokogiri::XML::Schema] The SAML 2.0 Protocol schema
    def self.schema
      @schema ||= File.open(File.expand_path('schemas/saml-schema-protocol-2.0.xsd', __dir__)) do |file|
        ::Nokogiri::XML::Schema(file)
      end
    end

    # @return [String|nil] Gets the Version attribute from the SAML Message if exists.
    def version(document)
      @version ||= root_attribute(document, 'Version')
    end

    # @return [String|nil] Gets the ID attribute from the SAML Message if exists.
    def id(document)
      @id ||= root_attribute(document, 'ID')
    end

    def root_attribute(document, attribute)
      document.at_xpath(
        "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest",
        { "p" => RubySaml::XML::NS_PROTOCOL }
      )&.[](attribute)
    end

    # Validates the SAML Message against the specified schema.
    # @param document [Nokogiri::XML::Document] The message that will be validated
    # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the message is invalid or not)
    # @param check_malformed_doc [Boolean] check_malformed_doc Enable or Disable the check for malformed XML
    # @return [Boolean] True if the XML is valid, otherwise False, if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    def valid_saml?(document, soft = true, check_malformed_doc: true)
      begin
        xml = RubySaml::XML.safe_load_nokogiri(document, check_malformed_doc: check_malformed_doc)
      rescue StandardError => error
        return false if soft
        raise ValidationError.new("XML load failed: #{error.message}")
      end

      self.class.schema.validate(xml).each do |schema_error|
        return false if soft
        raise ValidationError.new("#{schema_error.message}\n\n#{xml}")
      end

      true
    end

    private

    def check_malformed_doc?(settings)
      default_value = RubySaml::Settings::DEFAULTS[:check_malformed_doc]

      settings.nil? ? default_value : settings.check_malformed_doc
    end
  end
end
end
end
