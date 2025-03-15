# frozen_string_literal: true

require_relative '../test_helper'
require 'nokogiri'
require 'base64'
require 'openssl'

class NokogiriDecryptorTest < Minitest::Test
  XML_DSIG = "http://www.w3.org/2000/09/xmldsig#"
  XML_ENC = "http://www.w3.org/2001/04/xmlenc#"
  SAML_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
  SAML_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"

  describe "Nokogiri XML Decryptor" do
    let(:document_encrypted_assertion) { fixture(:unsigned_encrypted_adfs, false) }
    let(:noko_encrypted_assertion_doc) { Nokogiri::XML(document_encrypted_assertion) }
    let(:noko_encrypted_assertion_node) { noko_encrypted_assertion_doc.at_xpath('//saml:EncryptedAssertion|//EncryptedAssertion', 'saml' => SAML_ASSERTION) }

    let(:document_encrypted_attrs) { Base64.decode64(fixture(:response_encrypted_attrs)) }
    let(:noko_encrypted_attribute_doc) { Nokogiri::XML(document_encrypted_attrs) }

    let(:document_encrypted_nameid) { Base64.decode64(fixture(:response_encrypted_nameid)) }
    let(:noko_encrypted_nameid_doc) { Nokogiri::XML(document_encrypted_nameid) }

    let(:private_key) { OpenSSL::PKey::RSA.new(ruby_saml_key) }
    let(:another_private_key) { CertificateHelper.generate_private_key }
    let(:decryption_keys) { [private_key] }
    let(:multiple_decryption_keys) { [another_private_key, private_key] }

    describe '#decrypt_document' do
      it 'should decrypt a document with an encrypted assertion' do
        decrypted_doc = RubySaml::XML::Decryptor.decrypt_document(document_encrypted_assertion, decryption_keys)

        # The encrypted assertion should be removed
        assert_nil decrypted_doc.at_xpath('/p:Response/EncryptedAssertion', { 'p' => SAML_PROTOCOL })

        # An assertion should now be present
        refute_nil decrypted_doc.at_xpath('/p:Response/a:Assertion', { 'p' => SAML_PROTOCOL, 'a' => SAML_ASSERTION })
      end

      it 'should raise an error when no decryption keys are provided' do
        error = assert_raises(RubySaml::ValidationError) do
          RubySaml::XML::Decryptor.decrypt_document(document_encrypted_assertion, [])
        end
        assert_equal 'An EncryptedAssertion found and no SP private keys found to decrypt it', error.message
      end

      it 'should decrypt a document with multiple keys trying each one' do
        decrypted_doc = RubySaml::XML::Decryptor.decrypt_document(document_encrypted_assertion, multiple_decryption_keys)

        refute_nil decrypted_doc.at_xpath('/p:Response/a:Assertion', { 'p' => SAML_PROTOCOL, 'a' => SAML_ASSERTION })
      end
    end

    describe '#decrypt_assertion_from_document' do
      it 'should decrypt an encrypted assertion in a document' do
        decrypted_doc = RubySaml::XML::Decryptor.decrypt_assertion_from_document(noko_encrypted_assertion_doc, decryption_keys)

        # The encrypted assertion should be removed
        assert_nil decrypted_doc.at_xpath('/p:Response/EncryptedAssertion', { 'p' => SAML_PROTOCOL })

        # An assertion should now be present
        refute_nil decrypted_doc.at_xpath('/p:Response/a:Assertion', { 'p' => SAML_PROTOCOL, 'a' => SAML_ASSERTION })
      end

      it 'should handle documents without an encrypted assertion' do
        doc_without_encrypted_assertion = Nokogiri::XML("<Response xmlns='urn:oasis:names:tc:SAML:2.0:protocol'><Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'></Assertion></Response>")
        result = RubySaml::XML::Decryptor.decrypt_assertion_from_document(doc_without_encrypted_assertion, decryption_keys)

        # Should return the document unmodified
        assert_equal doc_without_encrypted_assertion.to_s, result.to_s
      end
    end

    describe '#decrypt_assertion' do
      it 'should decrypt an encrypted assertion node' do
        decrypted_assertion = RubySaml::XML::Decryptor.decrypt_assertion(noko_encrypted_assertion_node, decryption_keys)

        # Should return the Assertion node
        assert_equal 'Assertion', decrypted_assertion.name
        assert_equal SAML_ASSERTION, decrypted_assertion.namespace.href
      end

      it 'should raise an error when no decryption keys are provided' do
        error = assert_raises(RubySaml::ValidationError) do
          RubySaml::XML::Decryptor.decrypt_assertion(noko_encrypted_assertion_node, [])
        end
        assert_equal 'No decryption keys provided', error.message
      end
    end

    describe '#decrypt_nameid' do
      it 'should decrypt an encrypted name ID' do
        encrypted_nameid_node = noko_encrypted_nameid_doc.at_xpath('//saml:EncryptedID', { 'saml' => SAML_ASSERTION })
        decrypted_nameid = RubySaml::XML::Decryptor.decrypt_nameid(encrypted_nameid_node, decryption_keys)

        # Should return the NameID node
        assert_equal 'NameID', decrypted_nameid.name
        assert_equal SAML_ASSERTION, decrypted_nameid.namespace.href
        assert_equal 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', decrypted_nameid['Format']
        assert_equal 'test@onelogin.com', decrypted_nameid.content
      end

      it 'should raise an error when no decryption keys are provided' do
        encrypted_nameid_node = noko_encrypted_nameid_doc.at_xpath('//saml:EncryptedID', { 'saml' => SAML_ASSERTION })
        error = assert_raises(RubySaml::ValidationError) do
          RubySaml::XML::Decryptor.decrypt_nameid(encrypted_nameid_node, [])
        end
        assert_equal 'No decryption keys provided', error.message
      end
    end

    describe '#decrypt_attribute' do
      it 'should decrypt an encrypted attribute' do
        encrypted_attr_node = noko_encrypted_attribute_doc.at_xpath('//saml:EncryptedAttribute', { 'saml' => SAML_ASSERTION })
        decrypted_attr = RubySaml::XML::Decryptor.decrypt_attribute(encrypted_attr_node, decryption_keys)

        # Should return the Attribute node
        assert_equal 'Attribute', decrypted_attr.name
        assert_equal SAML_ASSERTION, decrypted_attr.namespace.href
      end
    end

    describe '#decrypt_node' do
      it 'should decrypt an EncryptedAssertion with a regexp matcher' do
        encrypted_data = noko_encrypted_assertion_doc.at_xpath('//saml:EncryptedAssertion', 'saml' => SAML_ASSERTION)
        decrypted_element = RubySaml::XML::Decryptor.decrypt_node(
          encrypted_data,
          %r{(.*</(\w+:)?Assertion>)}m,
          decryption_keys
        )

        # Should return the element matching the regexp
        fragment = Nokogiri::XML.fragment(decrypted_element)
        assert_equal 'Assertion', fragment.children.first.name
      end

      it 'should decrypt an EncryptedAttribute element with a regexp matcher' do
        encrypted_data = noko_encrypted_attribute_doc.at_xpath('//saml:EncryptedAttribute', 'saml' => SAML_ASSERTION)
        decrypted_element = RubySaml::XML::Decryptor.decrypt_node(
          encrypted_data,
          %r{(.*</(\w+:)?Attribute>)}m,
          decryption_keys
        )

        # Should return the element matching the regexp
        fragment = Nokogiri::XML.fragment(decrypted_element)
        assert_equal 'saml:Attribute', fragment.children.first.name
      end

      it 'should raise an error when no decryption keys are provided' do
        encrypted_data = noko_encrypted_assertion_node.at_xpath('./xenc:EncryptedData', 'xenc' => XML_ENC)
        error = assert_raises(RubySaml::ValidationError) do
          RubySaml::XML::Decryptor.decrypt_node(
            encrypted_data,
            %r{(.*</(\w+:)?Assertion>)}m,
            []
          )
        end
        assert_equal 'No decryption keys provided', error.message
      end
    end

    describe 'error handling' do
      it 'should raise ArgumentError when private keys are not RSA keys' do
        invalid_keys = ['not a key', 123]

        assert_raises(ArgumentError) do
          RubySaml::XML::Decryptor.decrypt_assertion(noko_encrypted_assertion_node, invalid_keys)
        end
      end

      it 'should handle missing EncryptedData elements gracefully' do
        # Create a node without the expected encrypted data structure
        invalid_node = Nokogiri::XML('<EncryptedAssertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"></EncryptedAssertion>').root

        assert_raises(NoMethodError) do
          RubySaml::XML::Decryptor.decrypt_assertion(invalid_node, decryption_keys)
        end
      end
    end

    describe '.decrypt_node_with_multiple_keys' do
      let(:private_key) { ruby_saml_key }
      let(:invalid_key1) { CertificateHelper.generate_private_key }
      let(:invalid_key2) { CertificateHelper.generate_private_key }
      let(:settings) { RubySaml::Settings.new(:private_key => private_key.to_pem) }
      let(:response) { RubySaml::Response.new(signed_message_encrypted_unsigned_assertion, :settings => settings) }
      let(:encrypted) do
        response.document.xpath(
          "/p:Response/EncryptedAssertion | /p:Response/a:EncryptedAssertion",
          { "p" => "urn:oasis:names:tc:SAML:2.0:protocol", "a" => "urn:oasis:names:tc:SAML:2.0:assertion" }
        ).first
      end

      it 'successfully decrypts with the first private key' do
        assert_match(/\A<saml:Assertion/, RubySaml::XML::Decryptor.send(:decrypt_node_with_multiple_keys, encrypted, [private_key]))
      end

      it 'successfully decrypts with a subsequent private key' do
        assert_match(/\A<saml:Assertion/, RubySaml::XML::Decryptor.send(:decrypt_node_with_multiple_keys, encrypted, [invalid_key1, private_key]))
      end

      it 'raises an error when there is only one key and it fails to decrypt' do
        assert_raises OpenSSL::PKey::PKeyError do
          RubySaml::XML::Decryptor.send(:decrypt_node_with_multiple_keys, encrypted, [invalid_key1])
        end
      end

      it 'raises an error when all keys fail to decrypt' do
        assert_raises OpenSSL::PKey::PKeyError do
          RubySaml::XML::Decryptor.send(:decrypt_node_with_multiple_keys, encrypted, [invalid_key1, invalid_key2])
        end
      end

      it 'raises an error when private keys is an empty array' do
        assert_raises ArgumentError do
          RubySaml::XML::Decryptor.send(:decrypt_node_with_multiple_keys, encrypted, [])
        end
      end

      it 'raises an error when private keys is nil' do
        assert_raises ArgumentError do
          RubySaml::XML::Decryptor.send(:decrypt_node_with_multiple_keys, encrypted, [])
        end
      end

      %i[ecdsa dsa].each do |sp_key_algo|
        describe "#{sp_key_algo.upcase} private key" do
          let(:non_rsa_key) { CertificateHelper.generate_private_key(sp_key_algo) }

          it 'raises unsupported error' do
            assert_raises(ArgumentError, 'private_keys must be OpenSSL::PKey::RSA keys') do
              RubySaml::XML::Decryptor.send(:decrypt_node_with_multiple_keys, encrypted, [non_rsa_key])
            end
          end
        end
      end
    end
  end
end
