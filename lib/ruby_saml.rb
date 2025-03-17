# frozen_string_literal: true

require 'cgi'
require 'zlib'
require 'base64'
require 'time'
require 'nokogiri'

require 'ruby_saml/logging'
require 'ruby_saml/xml'
require 'ruby_saml/messages/sp/message_builder'
require 'ruby_saml/messages/sp/authn_request'
require 'ruby_saml/messages/sp/logout_request'
require 'ruby_saml/messages/sp/logout_response'
require 'ruby_saml/messages/idp/message_parser'
require 'ruby_saml/messages/idp/response'
require 'ruby_saml/messages/idp/assertion'
require 'ruby_saml/messages/idp/logout_request'
require 'ruby_saml/messages/idp/logout_response'

# TODO: Extract errors to have common base class
require 'ruby_saml/setting_error'
require 'ruby_saml/http_error'
require 'ruby_saml/validation_error'

require 'ruby_saml/attributes'
require 'ruby_saml/settings'
require 'ruby_saml/attribute_service'
require 'ruby_saml/metadata'
require 'ruby_saml/idp_metadata_parser'
require 'ruby_saml/pem_formatter'
require 'ruby_saml/utils'
require 'ruby_saml/version'

# @deprecated This alias adds compatibility with v1.x and will be removed in v2.1.0
OneLogin = Object
