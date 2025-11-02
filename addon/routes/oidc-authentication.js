import { assert } from "@ember/debug";
import Route from "@ember/routing/route";
import { inject as service } from "@ember/service";
import { v4 } from "uuid";

import getAbsoluteUrl from "ember-simple-auth-oidc/utils/absolute-url";
import {
  generatePkceChallenge,
  generateCodeVerifier,
} from "ember-simple-auth-oidc/utils/pkce";

export default class OIDCAuthenticationRoute extends Route {
  @service session;
  @service router;
  @service config;

  queryParams = {
    code: { refreshModel: false },
    state: { refreshModel: false },
    access_token: { refreshModel: false },
    id_token: { refreshModel: false },
    token_type: { refreshModel: false },
    expires_in: { refreshModel: false },
  };

  get redirectUri() {
    const { protocol, host } = location;
    const path = this.router.urlFor(this.routeName);
    return `${protocol}//${host}${path}`;
  }

  _redirectToUrl(url) {
    location.replace(url);
  }

  /**
   * Parse tokens from URL fragment (hash).
   * Implicit flow typically returns tokens in the URL fragment (after #).
   *
   * @returns {Object|null} Object containing token parameters or null if no fragment
   */
  _parseTokensFromFragment() {
    const hash = location.hash;
    if (!hash || hash.length <= 1) {
      return null;
    }

    // Remove leading # and parse as query string
    const params = new URLSearchParams(hash.substring(1));
    const result = {};

    // Extract token-related parameters
    if (params.has("access_token")) {
      result.access_token = params.get("access_token");
    }
    if (params.has("id_token")) {
      result.id_token = params.get("id_token");
    }
    if (params.has("token_type")) {
      result.token_type = params.get("token_type");
    }
    if (params.has("expires_in")) {
      result.expires_in = parseInt(params.get("expires_in"), 10);
    }
    if (params.has("state")) {
      result.state = params.get("state");
    }

    return Object.keys(result).length > 0 ? result : null;
  }

  async beforeModel(transition) {
    await this.config.loadConfig();

    const queryParams =
      (transition.to ? transition.to.queryParams : transition.queryParams) ||
      {};

    // Check if this is an implicit grant callback or authorization code callback
    // If so, skip prohibitAuthentication to allow re-authentication with new tokens
    const fragmentTokens = this._parseTokensFromFragment();
    const hasImplicitGrantTokens =
      fragmentTokens?.access_token || queryParams.access_token;
    const hasAuthorizationCode = queryParams.code;

    if (transition.from && !hasImplicitGrantTokens && !hasAuthorizationCode) {
      this.session.prohibitAuthentication(transition.from.name);
    }

    // PKCE Verifier has to be set in session, because we redirect
    if (this.config.enablePkce) {
      let pkceCodeVerifier = this.session.data.pkceCodeVerifier;

      if (!pkceCodeVerifier) {
        pkceCodeVerifier = generateCodeVerifier(96);
        this.session.set("data.pkceCodeVerifier", pkceCodeVerifier);
      }
    }
  }

  /**
   * Handle unauthenticated requests
   *
   * This handles three cases:
   *
   * 1. The URL contains tokens (implicit grant flow). In this case the
   *    client will authenticate with the provided tokens.
   *
   * 2. The URL contains an authentication code and a state (authorization code flow).
   *    In this case the client will try to authenticate with the given parameters.
   *
   * 3. The URL does not contain tokens or code. In this case the client
   *    will be redirected to the configured identity provider login mask, which will
   *    then redirect to this route after a successful login.
   *
   * @param {*} model The model of the route
   * @param {Ember.Transition} transition The current transition
   * @param {Object} transition.to The destination of the transition
   * @param {Object} transition.to.queryParams The query params of the transition
   * @param {String} transition.to.queryParams.code The authentication code given by the identity provider
   * @param {String} transition.to.queryParams.state The state given by the identity provider
   * @param {String} transition.to.queryParams.access_token The access token (implicit flow)
   * @param {String} transition.to.queryParams.id_token The ID token (implicit flow)
   */
  async afterModel(_, transition) {
    await this.config.loadConfig();

    if (!this.config.hasEndpointsConfigured) {
      throw new Error(
        "Please define all OIDC endpoints (auth, token, logout, userinfo)",
      );
    }

    const queryParams =
      (transition.to ? transition.to.queryParams : transition.queryParams) ||
      {};

    // Check for implicit grant tokens in URL fragment (hash)
    const fragmentTokens = this._parseTokensFromFragment();
    if (fragmentTokens?.access_token) {
      return await this._handleImplicitGrantCallback(fragmentTokens);
    }

    // Check for implicit grant tokens in query params
    if (queryParams.access_token) {
      const tokenParams = {
        access_token: queryParams.access_token,
        id_token: queryParams.id_token,
        expires_in: queryParams.expires_in
          ? parseInt(queryParams.expires_in, 10)
          : undefined,
        state: queryParams.state,
      };
      return await this._handleImplicitGrantCallback(tokenParams);
    }

    // Authorization code flow
    if (queryParams.code) {
      return await this._handleCallbackRequest(
        queryParams.code,
        queryParams.state,
        transition,
      );
    }

    return this._handleRedirectRequest(queryParams);
  }

  /**
   * Authenticate with tokens received directly from implicit grant flow.
   *
   * This will check if the passed state equals the state in the application to
   * prevent from CSRF attacks.
   *
   * @param {Object} tokenParams The token parameters
   * @param {String} tokenParams.access_token The access token
   * @param {String} tokenParams.id_token The ID token
   * @param {Number} tokenParams.expires_in Token expiry in seconds
   * @param {String} tokenParams.state The state (uuid4) passed by the identity provider
   */
  async _handleImplicitGrantCallback(tokenParams) {
    const { access_token, id_token, expires_in, state } = tokenParams;

    // Validate state to prevent CSRF attacks
    if (state && state !== this.session.data.state) {
      assert("State did not match");
    }

    this.session.set("data.state", undefined);

    // Clear URL hash to remove tokens from URL
    if (location.hash) {
      history.replaceState(null, "", location.pathname + location.search);
    }

    // Invalidate existing session if present to allow re-authentication with new tokens
    if (this.session.isAuthenticated) {
      await this.session.invalidate();
    }

    const data = {
      access_token,
      id_token,
      expires_in,
      redirectUri: this.redirectUri,
    };

    await this.session.authenticate("authenticator:oidc", data);
  }

  /**
   * Authenticate with the authentication code given by the identity provider in the redirect.
   *
   * This will check if the passed state equals the state in the application to
   * prevent from CSRF attacks.
   *
   * If the authentication fails, it will redirect to this route again but
   * remove application state and query params. This is very unlikely to happen.
   *
   * If the authentication succeeds the default behaviour of ember-simple-auth
   * will apply and redirect to the entry point of the authenticated part of
   * the application.
   *
   * @param {String} code The authentication code passed by the identity provider
   * @param {String} state The state (uuid4) passed by the identity provider
   */
  async _handleCallbackRequest(code, state) {
    if (state !== this.session.data.state) {
      assert("State did not match");
    }

    this.session.set("data.state", undefined);

    const data = {
      code,
      redirectUri: this.redirectUri,
    };

    if (this.config.enablePkce) {
      data.codeVerifier = this.session.data.pkceCodeVerifier;
    }

    await this.session.authenticate("authenticator:oidc", data);
  }

  /**
   * Redirect the client to the configured identity provider login.
   *
   * This will also generate a uuid4 state which the application stores to the
   * local storage. When authenticating, the state passed by the identity provider needs to
   * match this state, otherwise the authentication will fail to prevent from
   * CSRF attacks.
   */
  _handleRedirectRequest(queryParams) {
    const state = v4();

    // Store state to session data
    this.session.set("data.state", state);

    /**
     * Store the `nextURL` in the localstorage so when the user returns after
     * the login he can be sent to the initial destination.
     */
    if (!this.session.data.nextURL) {
      const url = this.session.attemptedTransition?.intent?.url;
      this.session.set("data.nextURL", url);
    }

    // forward `login_hint` query param if present
    const key = this.config.configuration.loginHintName || "login_hint";

    let search = [
      `client_id=${this.config.clientId}`,
      `redirect_uri=${this.redirectUri}`,
      `response_type=code`,
      `state=${state}`,
      `scope=${this.config.scope}`,
      queryParams[key] ? `${key}=${queryParams[key]}` : null,
    ];

    if (this.config.enablePkce) {
      const pkceChallenge = generatePkceChallenge(
        this.session.data.pkceCodeVerifier,
      );
      search.push(`code_challenge=${pkceChallenge}`);
      search.push("code_challenge_method=S256");
    }

    if (this.config.audience) {
      search.push(`audience=${this.config.audience}`);
    }

    search = search.filter(Boolean).join("&");

    this._redirectToUrl(
      `${getAbsoluteUrl(this.config.authEndpoint, this.config.host)}?${search}`,
    );
  }
}
