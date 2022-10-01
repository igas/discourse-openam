# frozen_string_literal: true

# name: discourse-openam
# about: ForgeRock AM SSO integration
# version: 0.1
# authors: Igor Kapkov (igas), Robert Krzysztoforski (brissenden)
# url: https://github.com/jnsolutions/discourse-openam

after_initialize do
  class OpenamCurrentUserProvider < Auth::CurrentUserProvider
    CURRENT_USER_KEY ||= '_OPENAM_CURRENT_USER'
    TOKEN_COOKIE ||= '_oam_t'

    def initialize(env)
      @env = env
      @request = Rack::Request.new(env)
    end

    def current_user
      return @env[CURRENT_USER_KEY] if @env.key?(CURRENT_USER_KEY)

      @env[CURRENT_USER_KEY] = User.find_by(username: @env['HTTP_X_FORWARDED_USER'])
    end

    # Log on a user and set cookies and session etc.
    def log_on_user(user, _session, cookies)
      unless user.auth_token && user.auth_token.length == 32
        user.auth_token = SecureRandom.hex(16)
        user.save!
      end
      cookies.permanent[TOKEN_COOKIE] = { value: user.auth_token, httponly: true }
      make_developer_admin(user)
      @env[CURRENT_USER_KEY] = user
    end

    def make_developer_admin(user)
      if user.active? &&
         !user.admin &&
         Rails.configuration.respond_to?(:developer_emails) &&
         Rails.configuration.developer_emails.include?(user.email)
        user.admin = true
        user.save
      end
    end

    # API has special rights return true if api was detected
    def is_api?
      false
    end

    def is_user_api?
      false
    end

    # We may need to know very early on in the middleware if an auth token
    # exists, to optimise caching
    def has_auth_cookie?
      cookie = @request.cookies[TOKEN_COOKIE]
      !cookie.nil? && cookie.length == 32
    end

    def log_off_user(_session, _cookies)
      false
    end
  end

  Discourse.current_user_provider = OpenamCurrentUserProvider
end
