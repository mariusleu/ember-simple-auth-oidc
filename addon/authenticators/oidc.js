import { later } from "@ember/runloop";
import { inject as service } from "@ember/service";
import BaseAuthenticator from "ember-simple-auth/authenticators/base";
import { resolve } from "rsvp";
import { TrackedObject } from "tracked-built-ins";

import getAbsoluteUrl from "ember-simple-auth-oidc/utils/absolute-url";
import {
  isServerErrorResponse,
  isAbortError,
  isBadRequestResponse,
} from "ember-simple-auth-oidc/utils/errors";

export default class OidcAuthenticator extends BaseAuthenticator {
  @service router;
  @service session;
  @service config;

  /**
   * Authenticate the client with the given authentication code or tokens.
   *
   * This handles two flows:
   * 1. Authorization Code Flow: Receives a code and exchanges it for tokens
   * 2. Implicit Grant Flow: Receives tokens directly and processes them
   *
   * @param {Object} options The authentication options
   * @param {String} options.code The authentication code (for authorization code flow)
   * @param {String} options.access_token The access token (for implicit flow)
   * @param {String} options.id_token The ID token (for implicit flow)
   * @param {Number} options.expires_in Token expiry in seconds (for implicit flow)
   * @returns {Object} The parsed response data
   */
  async authenticate(options) {
    if (!this.config.hasEndpointsConfigured) {
      throw new Error(
        "Please define all OIDC endpoints (auth, token, userinfo)",
      );
    }

    const {
      isRefresh = false,
      redirectUri,
      customParams = {},
      access_token,
    } = options;

    if (isRefresh) {
      const DEFAULT_RETRY_COUNT = 0;
      return await this._refresh(
        this.session.data.authenticated.refresh_token,
        redirectUri,
        DEFAULT_RETRY_COUNT,
        customParams,
        this.session.data.authenticated.grant_type,
      );
    }

    // Implicit flow: tokens are already provided
    if (access_token) {
      return this._handleAuthResponse({
        access_token: options.access_token,
        id_token: options.id_token,
        expires_in: options.expires_in,
        refresh_token: options.refresh_token,
        redirectUri,
        grant_type: "implicit",
      });
    }

    // Authorization code flow: exchange code for tokens
    const body = this._buildBodyQuery(options);

    const response = await fetch(
      getAbsoluteUrl(this.config.tokenEndpoint, this.config.host),
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body,
      },
    );

    const isServerError = isServerErrorResponse(response);
    if (isServerError) throw new Error(response.message);

    const data = await response.json();

    // Failed request
    const isBadRequest = isBadRequestResponse(response);
    if (isBadRequest) throw data;

    // Store the redirect URI and grant type in the session for the restore call
    data.redirectUri = redirectUri;
    data.grant_type = "authorization_code";

    return this._handleAuthResponse(data);
  }

  /**
   * Invalidate the current ember simple auth session
   *
   * @return {Promise} The invalidate promise
   */
  invalidate() {
    return resolve(true);
  }

  /**
   * Invalidates the current session (of this application) and calls the
   * `end-session` endpoint of the authorization server, which will
   * invalidate all sessions which are handled by the authorization server
   * (possible for multiple applications).
   *
   * @param {String} idToken The id_token of the session to invalidate
   */
  singleLogout(idToken) {
    if (!this.config.endSessionEndpoint) {
      return;
    }

    const params = [];

    if (this.config.afterLogoutUri) {
      params.push(
        `post_logout_redirect_uri=${getAbsoluteUrl(
          this.config.afterLogoutUri,
        )}`,
      );
    }

    if (idToken) {
      params.push(`id_token_hint=${idToken}`);
    }

    this._redirectToUrl(
      `${getAbsoluteUrl(
        this.config.endSessionEndpoint,
        this.config.host,
      )}?${params.join("&")}`,
    );
  }

  _redirectToUrl(url) {
    location.replace(url);
  }

  /**
   * Restore the session after a page refresh. This will check if an access
   * token exists and tries to refresh said token. If the refresh token is
   * already expired, the auth backend will throw an error which will cause a
   * new login.
   *
   * For implicit grant flow (which may not provide refresh tokens), the session
   * is restored as long as it hasn't expired.
   *
   * @param {Object} sessionData The current session data
   * @param {String} sessionData.access_token The raw access token
   * @param {String} sessionData.refresh_token The raw refresh token (optional for implicit grant)
   * @returns {Promise} A promise which resolves with the session data
   */
  async restore(sessionData) {
    const { access_token, refresh_token, expireTime, redirectUri } =
      sessionData;

    // For implicit grant flow, we may not have a refresh token
    // In that case, just check if the session has expired
    if (!refresh_token) {
      if (!access_token) {
        throw new Error("Access token is missing");
      }

      // If the token is expired, we can't refresh it without a refresh_token
      if (expireTime && expireTime <= new Date().getTime()) {
        throw new Error("Token expired and no refresh token available");
      }

      // Token is still valid, restore the session
      return sessionData;
    }

    // Authorization code flow with refresh token
    if (expireTime && expireTime <= new Date().getTime()) {
      return await this._refresh(
        refresh_token,
        redirectUri,
        0,
        {},
        sessionData.grant_type,
      );
    }

    return sessionData;
  }

  /**
   * Refresh the access token
   *
   * @param {String} refresh_token The refresh token
   * @param {String} redirectUri The redirect URI
   * @param {Number} retryCount The number of retries attempted
   * @param {Object} customParams Custom parameters to include
   * @param {String} grant_type The original grant type
   * @returns {Object} The parsed response data
   */
  async _refresh(
    refresh_token,
    redirectUri,
    retryCount = 0,
    customParams = {},
    grant_type,
  ) {
    let isServerError = false;
    try {
      const body = this._buildBodyQuery({
        redirectUri,
        refresh_token,
        isRefresh: true,
        customParams,
      });

      const response = await fetch(
        getAbsoluteUrl(this.config.tokenEndpoint, this.config.host),
        {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body,
        },
      );
      isServerError = isServerErrorResponse(response);
      if (isServerError) throw new Error(response.message);

      const data = await response.json();

      // Failed refresh
      const isBadRequest = isBadRequestResponse(response);
      if (isBadRequest) return Promise.reject(data);

      // Store the redirect URI and grant type in the session for the restore call
      data.redirectUri = redirectUri;
      data.grant_type = grant_type;

      return this._handleAuthResponse(data);
    } catch (e) {
      if (
        (isServerError || isAbortError(e)) &&
        retryCount < this.config.amountOfRetries - 1
      ) {
        return new Promise((resolve) => {
          later(
            this,
            () =>
              resolve(
                this._refresh(
                  refresh_token,
                  redirectUri,
                  retryCount + 1,
                  customParams,
                  grant_type,
                ),
              ),
            this.config.retryTimeout,
          );
        });
      }
      throw e;
    }
  }

  /**
   * Request user information from the openid userinfo endpoint
   *
   * @param {String} accessToken The raw access token
   * @returns {Object} Object containing the user information
   */
  async _getUserinfo(accessToken) {
    const response = await fetch(
      getAbsoluteUrl(this.config.userinfoEndpoint, this.config.host),
      {
        headers: {
          Authorization: `${this.config.authPrefix} ${accessToken}`,
          Accept: "application/json",
        },
      },
    );

    const userinfo = await response.json();

    return userinfo;
  }

  /**
   * Handle an auth response. This method parses the token and schedules a
   * token refresh before the received token expires.
   *
   * @param {Object} response The raw response data
   * @param {String} response.access_token The raw access token
   * @param {String} response.refresh_token The raw refresh token
   * @param {Number} response.expires_in Seconds until access_token expires
   * @param {String} response.grant_type The grant type used (authorization_code or implicit)
   * @returns {Object} The authentication data
   */
  async _handleAuthResponse({
    access_token,
    refresh_token,
    expires_in,
    id_token,
    redirectUri,
    grant_type,
  }) {
    const userinfo = await this._getUserinfo(access_token);

    const expireInMilliseconds = expires_in
      ? expires_in * 1000
      : this.config.expiresIn;
    const expireTime =
      new Date().getTime() + expireInMilliseconds - this.config.refreshLeeway;

    return new TrackedObject({
      access_token,
      refresh_token,
      userinfo,
      id_token,
      expireTime,
      redirectUri,
      grant_type,
    });
  }

  /**
   * Builds query parameters string for the authorize or refresh request
   *
   * @param {*} options
   * @returns string
   */
  _buildBodyQuery({
    code,
    redirectUri,
    codeVerifier,
    isRefresh = false,
    refresh_token,
    customParams = {},
  }) {
    const bodyObject = {
      redirect_uri: redirectUri,
      client_id: this.config.clientId,
      grant_type: isRefresh ? "refresh_token" : "authorization_code",
      ...customParams,
    };

    if (!isRefresh && code) {
      bodyObject.code = code;
      if (this.config.enablePkce) {
        bodyObject.code_verifier = codeVerifier;
      }
    }

    if (isRefresh && refresh_token) {
      bodyObject.refresh_token = refresh_token;
    }

    const bodyQuery = Object.keys(bodyObject)
      .map((k) => `${k}=${encodeURIComponent(bodyObject[k])}`)
      .join("&");

    return bodyQuery;
  }
}
