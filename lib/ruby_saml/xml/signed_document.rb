# frozen_string_literal: true

require 'nokogiri'
require 'base64'
require 'openssl'

module RubySaml
  module XML
    # Module for handling XML signature validation using Nokogiri
    module SignedDocument
      extend self

      # Validates the document against a certificate fingerprint
      def validate_document(document, idp_cert_fingerprint, options = {})
        xml_doc = RubySaml::XML.safe_load_nokogiri(document)

        # Get cert from response
        # TODO: Remove relative path
        cert_element = xml_doc.at_xpath('//ds:X509Certificate', 'ds' => RubySaml::XML::DSIG)

        if cert_element
          base64_cert = cert_element.text.strip
          cert_text = Base64.decode64(base64_cert)
          begin
            cert = OpenSSL::X509::Certificate.new(cert_text)
          rescue OpenSSL::X509::CertificateError => e
            raise RubySaml::ValidationError.new("Document Certificate Error: #{e.message}")
          end

          if options[:fingerprint_alg]
            fingerprint_alg = RubySaml::XML.hash_algorithm(options[:fingerprint_alg]).new
          else
            fingerprint_alg = OpenSSL::Digest.new('SHA256')
          end

          fingerprint = fingerprint_alg.hexdigest(cert.to_der)

          # Check cert matches registered idp cert
          if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/, '').downcase
            raise RubySaml::ValidationError.new("Fingerprint mismatch")
          end

          base64_cert = Base64.encode64(cert.to_der)
        elsif options[:cert]
          base64_cert = Base64.encode64(options[:cert].to_pem)
        else
          raise RubySaml::ValidationError.new("Certificate element missing in response (ds:X509Certificate) and no cert provided in settings")
        end

        validate_signature(xml_doc, base64_cert)
      end

      # Validates the document with a certificate
      def validate_document_with_cert(document, idp_cert)
        xml_doc = RubySaml::XML.safe_load_nokogiri(document)

        # Get cert from response
        # TODO: Remove relative path
        cert_element = xml_doc.at_xpath('//ds:X509Certificate', 'ds' => RubySaml::XML::DSIG)

        if cert_element
          base64_cert = cert_element.text.strip
          cert_text = Base64.decode64(base64_cert)
          begin
            cert = OpenSSL::X509::Certificate.new(cert_text)
          rescue OpenSSL::X509::CertificateError => e
            raise RubySaml::ValidationError.new("Document Certificate Error: #{e.message}")
          end

          # Check saml response cert matches provided idp cert
          if idp_cert.to_pem != cert.to_pem
            raise RubySaml::ValidationError.new("Certificate of the Signature element does not match provided certificate")
          end
        end

        encoded_idp_cert = Base64.encode64(idp_cert.to_pem)
        validate_signature(xml_doc, encoded_idp_cert)
      end

      # Validates the signature using the provided certificate
      def validate_signature(document, base64_cert)
        xml_doc = RubySaml::XML.safe_load_nokogiri(document)

        raise RubySaml::ValidationError.new("Cert is missing") if base64_cert.nil?

        # Get signature node
        # TODO: Remove relative path
        sig_element = xml_doc.at_xpath('//ds:Signature', 'ds' => RubySaml::XML::DSIG)
        raise RubySaml::ValidationError.new("No Signature node found") if sig_element.nil?

        # Signature method
        sig_alg_node = sig_element.at_xpath('./ds:SignedInfo/ds:SignatureMethod', 'ds' => RubySaml::XML::DSIG)
        signature_hash_algorithm = RubySaml::XML.hash_algorithm(sig_alg_node)
        raise RubySaml::ValidationError.new("No Signature Hash Algorithm Method found") if signature_hash_algorithm.nil?

        # Get signature
        base64_signature_node = sig_element.at_xpath('./ds:SignatureValue', 'ds' => RubySaml::XML::DSIG)
        raise RubySaml::ValidationError.new("No SignatureValue node found") if base64_signature_node.nil?

        base64_signature_text = base64_signature_node.text.strip
        signature = Base64.decode64(base64_signature_text) if base64_signature_text
        raise RubySaml::ValidationError.new("No Signature found") if signature.nil?

        # Canonicalization method
        canon_method_node = sig_element.at_xpath('./ds:SignedInfo/ds:CanonicalizationMethod', 'ds' => RubySaml::XML::DSIG)
        canon_algorithm = RubySaml::XML.canon_algorithm(canon_method_node)

        signed_info_element = sig_element.at_xpath('./ds:SignedInfo', 'ds' => RubySaml::XML::DSIG)
        cached_signed_info = signed_info_element.canonicalize(canon_algorithm)
        raise RubySaml::ValidationError.new("No canonized SignedInfo") if cached_signed_info.nil?

        # Now handle the referenced XML
        ref = signed_info_element.at_xpath('./ds:Reference', 'ds' => RubySaml::XML::DSIG)
        raise RubySaml::ValidationError.new("No Reference node found") if ref.nil?

        # Make a copy of the document and remove the signature for canonicalization
        xml_doc_without_sig = xml_doc.clone
        # TODO: Remove relative path
        sig_element_in_clone = xml_doc_without_sig.at_xpath('//ds:Signature', 'ds' => RubySaml::XML::DSIG)
        sig_element_in_clone.remove if sig_element_in_clone

        signed_element_id_value = signed_element_id(xml_doc)
        # TODO: Remove relative path
        reference_nodes = xml_doc_without_sig.xpath("//*[@ID='#{signed_element_id_value}']")

        hashed_element = reference_nodes[0]
        raise RubySaml::ValidationError.new("No referenced element found with ID: #{signed_element_id_value}") if hashed_element.nil?

        # Process transforms to determine canonicalization algorithm
        transform_canon_algorithm = process_transforms(ref, canon_algorithm)

        # Extract inclusive namespaces if present
        inclusive_namespaces = extract_inclusive_namespaces(xml_doc)

        referenced_xml = hashed_element.canonicalize(transform_canon_algorithm, inclusive_namespaces)
        raise RubySaml::ValidationError.new("No referenced XML") if referenced_xml.nil?

        # Get digest method
        digest_method_node = ref.at_xpath('./ds:DigestMethod', 'ds' => RubySaml::XML::DSIG)
        digest_algorithm = RubySaml::XML.hash_algorithm(digest_method_node)

        # Calculate hash from referenced XML
        hash = digest_algorithm.digest(referenced_xml)

        # Get DigestValue from document
        encoded_digest_value = ref.at_xpath('./ds:DigestValue', 'ds' => RubySaml::XML::DSIG)
        encoded_digest_value_text = encoded_digest_value&.text&.strip
        digest_value = encoded_digest_value_text.nil? ? nil : Base64.decode64(encoded_digest_value_text)

        # Compare the computed "hash" with the "signed" hash
        unless hash && hash == digest_value
          raise RubySaml::ValidationError.new("Digest mismatch")
        end

        # Verify signature
        cert_text = Base64.decode64(base64_cert)
        cert = OpenSSL::X509::Certificate.new(cert_text)

        begin
          signature_verified = cert.public_key.verify(
            signature_hash_algorithm.new,
            signature,
            cached_signed_info
          )
          raise RubySaml::ValidationError.new("Key validation error") unless signature_verified
        rescue OpenSSL::PKey::PKeyError => e
          raise RubySaml::ValidationError.new("Key validation error: #{e.message}")
        end

        true
      end

      # Extract the signed element ID from a document
      def signed_element_id(document)
        xml_doc = RubySaml::XML.safe_load_nokogiri(document)

        # TODO: Remove relative path
        reference_element = xml_doc.at_xpath(
          '//ds:Signature/ds:SignedInfo/ds:Reference',
          'ds' => RubySaml::XML::DSIG
        )

        return nil if reference_element.nil?

        uri = reference_element['URI']
        return nil if uri.nil?

        # Remove the leading '#' character
        sei = uri[1..]
        sei.nil? ? reference_element.parent.parent.parent['ID'] : sei
      end
      alias_method :extract_signed_element_id, :signed_element_id

      # def extract_signed_element_id(document)
      #   reference_element = RubySaml::XML.safe_load_nokogiri(document).at_xpath(
      #     '//ds:Signature/ds:SignedInfo/ds:Reference',
      #     { 'ds' => RubySaml::XML::DSIG }
      #   )
      #
      #   has_uri = !reference_element['URI']&.[](1..).nil?
      #   reference_element.parent.parent.parent['ID'] if has_uri
      # end

      private

      def process_transforms(ref, canon_algorithm)
        transforms = ref.xpath('./ds:Transforms/ds:Transform', 'ds' => RubySaml::XML::DSIG)

        transforms.each do |transform_element|
          next unless transform_element['Algorithm']

          new_algorithm = RubySaml::XML.canon_algorithm(transform_element, default: false)
          canon_algorithm = new_algorithm if new_algorithm
        end

        canon_algorithm
      end

      def extract_inclusive_namespaces(document)
        element = document.at_xpath('//ec:InclusiveNamespaces', 'ec' => RubySaml::XML::C14N)
        return nil unless element

        prefix_list = element['PrefixList']
        return nil unless prefix_list

        prefix_list.split
      end
    end
  end
end
