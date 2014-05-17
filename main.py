import json

import webapp2

from webapp2_extras import auth, sessions

from simpleauth import SimpleAuthHandler


class SessionHandler(webapp2.RequestHandler):
  def dispatch(self):
    self.session_store = sessions.get_store(request=self.request)
    try:
      webapp2.RequestHandler.dispatch(self)
    finally:
      self.session_store.save_sessions(self.response)

  @webapp2.cached_property
  def session(self):
    return self.session_store.get_session()

  @webapp2.cached_property
  def auth(self):
      return auth.get_auth()

  @webapp2.cached_property
  def current_user(self):
    user_dict = self.auth.get_user_by_session()
    if user_dict is None:
      return None
    return self.auth.store.user_model.get_by_id(user_dict['user_id'])

  @property
  def logged_in(self):
    return self.current_user is not None



class AuthHandler(SessionHandler, SimpleAuthHandler):

  OAUTH2_CSRF_STATE = True

  def head(self, *args):
    # for twitter. twitter requires HEAD
    pass

  def _callback_uri_for(self, provider):
    return self.uri_for('auth_callback', provider=provider, _scheme="https", _netloc="auth.mayone.us")

  def _get_consumer_info_for(self, provider):
    return {
      # oauth2
      "google":       ("<appid>", "<appsecret>",
                       "https://www.googleapis.com/auth/userinfo.profile"),
      "linkedin2":    ("<key>", "<secret>", "r_basicprofile"),
      "facebook":     ("688473597886416", "54c7e9bb474c86efeef7333ec57a7897",
                       "user_about_me"),
      "windows_live": ("<clientid>", "<clientsecret>", "wl.signin"),
      "foursquare":   ("<clientid>", "<clientsecret>", "authorization_code"),

      # oauth1
      "twitter":      ("<consumerkey>", "<consumersecret>"),
      "linkedin":     ("<key>", "<secret>"),

      #openid needs nothing
    }[provider]

  def _on_signin(self, data, auth_info, provider):
    if self.logged_in:
      # oh, we already have a user model logged in. hmm, we should probably
      # join these users. for now we're just going to ignore this log in
      # attempt
      self.redirect(self.uri_for("current_user"))
      return

    auth_id = "%s:%s" % (provider, data["id"])
    user_data = {}
    user_data["name"] = data[{
        "facebook": "name",
        "google": "name",
        "windows_live": "name",
        "twitter": "screen_name",
        "linkedin": "first-name",
        "linkedin2": "first-name",
        "foursquare": "firstName",
        "openid": "nickname"}[provider]]

    user = self.auth.store.user_model.get_by_auth_id(auth_id)

    if user:
      user.populate(**user_data)
      user.put()
      self.auth.set_session(self.auth.store.user_to_dict(user))
      self.redirect(self.uri_for("current_user"))
      return

    okay, user = self.auth.store.user_model.create_user(auth_id, **user_data)
    if not okay:
      # TODO: handle this error
      self.redirect("/")
      return

    self.auth.set_session(self.auth.store.user_to_dict(user))
    self.redirect(self.uri_for("current_user"))

  def logout(self):
    self.auth.unset_session()
    self.redirect(self.uri_for("current_user"))


class CurrentUserHandler(SessionHandler):
  def get(self):
    user = self.current_user
    if user is not None:
      self.response.headers["Content-Type"] = "application/json"
      self.response.write(json.dumps({
        "user": {
          "user_id": user.get_id(),
          "name": user.name,
        }
      }))
    else:
      links = {}
      for provider in ["google", "linkedin2", "facebook", "windows_live",
                       "foursquare", "twitter", "linkedin"]:
        links[provider] = "/auth/" + provider
      # TODO: add openid peeps
      self.response.write(json.dumps({
        "logged_out": True,
        "login_links": links,
      }))


app = webapp2.WSGIApplication([
  webapp2.Route('/current_user', handler=CurrentUserHandler,
                name='current_user'),
  webapp2.Route('/logout', handler=AuthHandler,
                handler_method='logout', name='logout'),

  webapp2.Route('/auth/<provider>', handler=AuthHandler,
                handler_method='_simple_auth', name='auth_login'),
  webapp2.Route('/auth/<provider>/callback', handler=AuthHandler,
                handler_method='_auth_callback', name='auth_callback'),

], config={
  "webapp2_extras.sessions": {
    "cookie_name": "_simpleauth_sess",
    "secret_key": "<secret_key>",
  },
  "webapp2_extras.auth": {
    "user_attributes": [],
  },
}, debug=False)
