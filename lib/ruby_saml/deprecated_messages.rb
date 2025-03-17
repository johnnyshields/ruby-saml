

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
# frozen_string_literal: true

module RubySaml
  def self.warn_deprecated(klass, target_class)
    warn "[DEPRECATION] #{klass} is deprecated. Please use #{target_class} instead."
  end

  class Authrequest < RubySaml::Messages::Sp::AuthnRequest
    def initialize(...)
      warn_deprecated(self.class.name, "RubySaml::Messages::Sp::AuthnRequest")
      super
    end
  end

  class Response < RubySaml::Messages::Idp::Response
    def initialize(...)
      warn_deprecated(self.class.name, "RubySaml::Messages::Idp::Response")
      super
    end
  end

  class Logoutrequest < RubySaml::Messages::Sp::LogoutRequest
    def initialize(...)
      warn_deprecated(self.class.name, "RubySaml::Messages::Sp::LogoutRequest")
      super
    end
  end

  class Logoutresponse < RubySaml::Messages::Idp::LogoutResponse
    def initialize(...)
      warn_deprecated(self.class.name, "RubySaml::Messages::Idp::LogoutResponse")
      super
    end
  end

  class SloLogoutrequest < RubySaml::Messages::Idp::LogoutRequest
    def initialize(...)
      warn_deprecated(self.class.name, "RubySaml::Messages::Idp::LogoutRequest")
      super
    end
  end

  class SloLogoutresponse < RubySaml::Messages::Sp::LogoutResponse
    def initialize(...)
      warn_deprecated(self.class.name, "RubySaml::Messages::Sp::LogoutResponse")
      super
    end
  end
end