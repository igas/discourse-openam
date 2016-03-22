class OpenamCurrentUserProvider < Auth::CurrentUserProvider
  CURRENT_USER_KEY ||= "_OPENAM_CURRENT_USER".freeze
  TOKEN_COOKIE ||= "_oam_t".freeze

  def initialize(env)
    @env = env
    @request = Rack::Request.new(env)
  end

  def current_user
    return @env[CURRENT_USER_KEY] if @env.key?(CURRENT_USER_KEY)
    @env[CURRENT_USER_KEY] = User.find_by(email: @env['HTTP_X_FORWARDED_USER'])
  end

  # log on a user and set cookies and session etc.
  def log_on_user(user, session, cookies)
    unless user.auth_token && user.auth_token.length == 32
      user.auth_token = SecureRandom.hex(16)
      user.save!
    end
    cookies.permanent[TOKEN_COOKIE] = { value: user.auth_token, httponly: true }
    make_developer_admin(user)
    @env[CURRENT_USER_KEY] = user
  end

  def make_developer_admin(user)
    if  user.active? &&
        !user.admin &&
        Rails.configuration.respond_to?(:developer_emails) &&
        Rails.configuration.developer_emails.include?(user.email)
      user.admin = true
      user.save
    end
  end

  # api has special rights return true if api was detected
  def is_api?
    false
  end

  # we may need to know very early on in the middleware if an auth token
  # exists, to optimise caching
  def has_auth_cookie?
    cookie = @request.cookies[TOKEN_COOKIE]
    !cookie.nil? && cookie.length == 32
  end

  def log_off_user(_session, _cookies)
    false
  end
end

after_initialize do
  Discourse.current_user_provider = OpenamCurrentUserProvider
end
