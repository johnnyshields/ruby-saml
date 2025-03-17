

module RubySaml
  def self.warn_deprecated_message

  end

  class Authrequest < RubySaml::Messages::Sp::AuthnRequest
    def initialize
      warn_deprecated_message(self)
      super
    end
  end

  class Response < RubySaml::Messages::Idp::Response
    def initialize(...)
      warn
      super
    end
  end

  class Logoutrequest < RubySaml::Messages::Sp::LogoutRequest

  end

  class Logoutresponse < RubySaml::Messages::Idp::LogoutResponse

  end

  class SloLogoutrequest < RubySaml::Messages::Idp::LogoutRequest

  end

  class SloLogoutresponse < RubySaml::Messages::Sp::LogoutResponse

  end
end
