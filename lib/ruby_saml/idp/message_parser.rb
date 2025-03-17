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
# frozen_string_literal: true

module RubySaml
  module Messages
    # Absolute core of all SAML message functionality
    class Message
      attr_accessor :errors

      def initialize
        @errors = []
      end

      # Reset the errors array
      def reset_errors!
        @errors = []
      end

      # Append an error and handle soft mode
      def append_error(error_msg, soft = true)
        @errors << error_msg
        raise ValidationError.new(error_msg) unless soft
        false
      end

      # Common SAML schema for validation
      def self.schema
        @schema ||= File.open(File.expand_path('schemas/saml-schema-protocol-2.0.xsd', __dir__)) do |file|
          ::Nokogiri::XML::Schema(file)
        end
      end

      # Extract a root attribute from the SAML message
      def extract_from_document(document, xpath, attribute = nil)
        node = document.at_xpath(xpath, {
          "p" => RubySaml::XML::NS_PROTOCOL,
          "a" => RubySaml::XML::NS_ASSERTION,
          "ds" => RubySaml::XML::DSIG
        })

        attribute ? node&.[](attribute) : node&.text
      end

      # Build clean attributes by removing empty values
      def clean_attributes(attributes)
        attributes.compact.reject { |_, v| v.respond_to?(:empty?) && v.empty? }
      end

      # Validate against schema
      def validate_schema(document, soft = true)
        begin
          xml = RubySaml::XML.safe_load_nokogiri(document)
        rescue StandardError => error
          return append_error("XML load failed: #{error.message}", soft)
        end

        self.class.schema.validate(xml).each do |error|
          return append_error("Schema validation failed: #{error.message}", soft)
        end

        true
      end
    end
  end
end

# frozen_string_literal: true

module RubySaml
  module Messages
    module Validation
      # Run validations and handle error collection
      def run_validations(validations, collect_errors = false)
        reset_errors!

        if collect_errors
          validations.each { |validation| send(validation) }
          @errors.empty?
        else
          validations.all? { |validation| send(validation) }
        end
      end

      # Validate the SAML version is 2.0
      def validate_version
        version = extract_from_document(document, "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest", 'Version')
        return true if version == "2.0"
        append_error("Unsupported SAML version", soft)
      end

      # Validate ID exists
      def validate_id
        id = extract_from_document(document, "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest", 'ID')
        return true if id
        append_error("Missing ID attribute", soft)
      end

      # Validate XML structure
      def validate_structure
        validate_schema(document, soft)
      end

      # Validate issuer matches expected value
      def validate_issuer(issuer_value, expected_issuer)
        return true if expected_issuer.nil? || issuer_value.nil?

        unless RubySaml::Utils.uri_match?(issuer_value, expected_issuer)
          return append_error("Issuer mismatch, expected: <#{expected_issuer}>, got: <#{issuer_value}>", soft)
        end

        true
      end

      # Validate time condition
      def validate_time_condition(actual_time, comparison_time, before_or_after, drift = 0)
        now = Time.now.utc
        drift_text = drift > 0 ? "#{drift.ceil}s" : ""

        if before_or_after == :before && now < (actual_time - drift)
          return append_error("Current time is earlier than #{comparison_time} (#{now} < #{actual_time}#{" - " + drift_text if drift > 0})", soft)
        elsif before_or_after == :after && now >= (actual_time + drift)
          return append_error("Current time is on or after #{comparison_time} (#{now} >= #{actual_time}#{" + " + drift_text if drift > 0})", soft)
        end

        true
      end

      # Get allowed clock drift
      def allowed_clock_drift
        (options&.dig(:allowed_clock_drift) || 0).to_f.abs + Float::EPSILON
      end
    end
  end
end