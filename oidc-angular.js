/// <reference path = "./bower_components/angular/angular.js"/>
/// <reference path = "./bower_components/oidc-client/oidc-client.js"/>
/// <reference path = "./bower_components/oidc-token-manager/oidc-token-manager.js"/>

'use strict';
(function () {

    var REQUEST_TYPE = {
        LOGIN: 'LOGIN',
        RENEW_TOKEN: 'RENEW_TOKEN',
        ID_TOKEN: 'ID_TOKEN',
        UNKNOWN: 'UNKNOWN'
    };
    var CONSTANTS = {
        ACCESS_TOKEN: 'access_token',
        EXPIRES_IN: 'expires_in',
        ID_TOKEN: 'id_token',
        STATE: 'state',
        ERROR_DESCRIPTION: 'error_description',
        SESSION_STATE: 'session_state',
        STORAGE: {
            TOKEN_KEYS: 'adal.token.keys',
            ACCESS_TOKEN_KEY: 'adal.access.token.key',
            EXPIRATION_KEY: 'adal.expiration.key',
            START_PAGE: 'adal.start.page',
            START_PAGE_PARAMS: 'adal.start.page.params',
            FAILED_RENEW: 'adal.failed.renew',
            STATE_LOGIN: 'adal.state.login',
            STATE_RENEW: 'adal.state.renew',
            STATE_RENEW_RESOURCE: 'adal.state.renew.resource',
            STATE_IDTOKEN: 'adal.state.idtoken',
            NONCE_IDTOKEN: 'adal.nonce.idtoken',
            SESSION_STATE: 'adal.session.state',
            USERNAME: 'adal.username',
            IDTOKEN: 'adal.idtoken',
            ERROR: 'adal.error',
            ERROR_DESCRIPTION: 'adal.error.description',
            LOGIN_REQUEST: 'adal.login.request',
            LOGIN_ERROR: 'adal.login.error'
        },
        RESOURCE_DELIMETER: '|',
        ERR_MESSAGES: {
            NO_TOKEN: 'User is not authorized'
        },
        LOGGING_LEVEL: {
            ERROR: 0,
            WARN: 1,
            INFO: 2,
            VERBOSE: 3
        },
        LEVEL_STRING_MAP: {
            0: 'ERROR:',
            1: 'WARNING:',
            2: 'INFO:',
            3: 'VERBOSE:'
        }
    };



    var eventPrefix = 'oidcauth:';

    var unauthorizedEvent = eventPrefix + 'unauthorized';
    var tokenExpiredEvent = eventPrefix + 'tokenExpired';
    var tokenMissingEvent = eventPrefix + 'tokenMissing';
    var tokenExpiresSoonEvent = eventPrefix + 'tokenExpires';

    var loggedInEvent = eventPrefix + 'loggedIn';
    var loggedOutEvent = eventPrefix + 'loggedOut';

    var silentRefreshStartedEvent = eventPrefix + 'silentRefreshStarted';
    var silentRefreshSuceededEvent = eventPrefix + 'silentRefreshSucceded';
    var silentRefreshFailedEvent = eventPrefix + 'silentRefreshFailed';
    var silentRefreshTimeoutEvent = eventPrefix + 'silentRefreshTimeout';

    // Module registrarion
    var oidcmodule = angular.module('oidc-angular', ['base64', 'ngStorage', 'ngRoute']);

    oidcmodule.constant("oidcEvents", {
        unauthorizedEvent: eventPrefix + 'unauthorized',
        tokenExpiredEvent: eventPrefix + 'tokenExpired',
        tokenMissingEvent: eventPrefix + 'tokenMissing',
        tokenExpiresSoonEvent: eventPrefix + 'tokenExpires',

        loggedInEvent: eventPrefix + 'loggedIn',
        loggedOutEvent: eventPrefix + 'loggedOut',

        silentRefreshStartedEvent: eventPrefix + 'silentRefreshStarted',
        silentRefreshSuceededEvent: eventPrefix + 'silentRefreshSucceded',
        silentRefreshFailedEvent: eventPrefix + 'silentRefreshFailed',
        silentRefreshTimeoutEvent: eventPrefix + 'silentRefreshTimeout'
    })

    oidcmodule.config(['$httpProvider', '$routeProvider', '$locationProvider', function ($httpProvider, $routeProvider, $locationProvider) {
        // Required html5
        $locationProvider.html5Mode(true).hashPrefix('!');
        // Register callback route
        // $routeProvider.
        //     when('/auth/callback/:data', {
        //         template: '',
        //         controller: ['$auth', '$routeParams', function ($auth, $routeParams) {
        //             console.debug('oidc-angular: handling login-callback');
        //             $auth.handleSignInCallback($routeParams.data);
        //         }]
        //     }).
        //     when('/auth/clear', {
        //         template: '',
        //         controller: ['$auth', function ($auth) {
        //             console.debug('oidc-angular: handling logout-callback');
        //             $auth.handleSignOutCallback();
        //         }]
        //     });
        console.debug('oidc-angular: callback routes registered.')
    }]);

    oidcmodule.provider("$auth", ['$routeProvider', function ($routeProvider) {
        var _oidcClient = null;
         
        // Default configuration
        var config = {
            issuer: null,
            basePath: null,
            clientId: null,
            apiUrl: '/api/',
            responseType: 'id_token token',
            scope: "openid profile",
            redirectUri: (window.location.origin || window.location.protocol + '//' + window.location.host) + window.location.pathname + '#/auth/callback/',
            postLogoutRedirectUri: (window.location.origin || window.location.protocol + '//' + window.location.host) + window.location.pathname + '#/auth/clear',
            state: "",
            authorizationEndpoint: 'connect/authorize',
            revocationEndpoint: 'connect/revocation',
            endSessionEndpoint: 'connect/endsession',
            advanceRefresh: 300,
            enableRequestChecks: false,
        };

        this.init = function (configOptions, httpProvider) {
            if (configOptions) {
                angular.extend(config, configOptions);

                if (httpProvider && httpProvider.interceptors) {
                    httpProvider.interceptors.push('oidcHttpInterceptor');
                }

                // create instance with given config
                _oidcClient = new OidcClient({
                    client_id: config.clientId,
                    redirect_uri: config.redirectUri,
                    post_logout_redirect_uri: config.postLogoutRedirectUri,
                    response_type: config.responseType,
                    scope: config.scope,
                    authority: config.basePath,
                    authorization_endpoint: config.basePath + '/' + config.authorizationEndpoint
                }
                    );
            } else {
                throw new Error('You must set configOptions, when calling init');
            }
            // loginresource is used to set authenticated status
            //updateDataFromCache(_adal.config.loginResource);
        };
        this.$get = ['$q', '$document', '$rootScope', '$localStorage', '$location', '$window', 'tokenService', function ($q, $document, $rootScope, $localStorage, $location, $window, tokenService) {
            var init = function () {
                if ($localStorage['logoutActive']) {
                    delete $localStorage['logoutActive'];
                    tokenService.clearTokens();
                }
                if ($localStorage['refreshRunning']) {
                    delete $localStorage['refreshRunning'];
                }
            };
            var login = function (localRedirect) {
                _oidcClient.createTokenRequestAsync().then(function (request) {
                    $localStorage['localRedirect'] = localRedirect;
                    console.debug('Expected state: ' + request.request_state.state + ' startPage:' + $window.location);
                    $localStorage[CONSTANTS.STORAGE.LOGIN_REQUEST] = $window.location;
                    $localStorage[CONSTANTS.STORAGE.LOGIN_ERROR] = '';
                    $localStorage[CONSTANTS.STORAGE.STATE_LOGIN] = request.request_state.state;
                    $localStorage[CONSTANTS.STORAGE.NONCE_IDTOKEN] = request.request_state.nonce;
                    $localStorage[CONSTANTS.STORAGE.FAILED_RENEW] = '';
                    $localStorage[CONSTANTS.STORAGE.ERROR] = '';
                    $localStorage[CONSTANTS.STORAGE.ERROR_DESCRIPTION] = '';
                    window.location.replace(request.url);
                }, function (err) {
                    console.error("cannot create authenticate request" + err);
                });
            };

            function _saveItem(key, value) {
                $localStorage[key] = value;
            }
            function _getItem(key) {
                return $localStorage[key]
            }

            var logout = function () {
                var idToken = tokenService.getIdToken();
                _oidcClient.createLogoutRequestAsync(idToken).then(function (url) {
                    $localStorage['logoutActive'] = true;
                    window.location = url;
                });
            };

            var locationChangeHandler = function () {
                var hash = $window.location.hash;
                if (isCallback(hash)) {
                    console.debug("oidc-angular: Processing callback information", hash);
                    var requestInfo = getRequestInfo(hash);


                    //if ($location.$$html5) {
                    //    $window.location = $window.location.origin + $window.location.pathname;
                    //} else {
                    //    $window.location.hash = '';
                    // }


                    var id_token = requestInfo.parameters[CONSTANTS.ID_TOKEN];
                    var state = requestInfo.parameters[CONSTANTS.STATE];
                    if (id_token) {
                        if (state === 'refresh') {
                            handleSilentRefreshCallback(id_token);
                        }
                        else {
                            handleImplicitFlowCallback(id_token);
                        }
                    }
                }
            }

            function isCallback(hash) {
                hash = _getHash(hash);
                var parameters = _deserialize(hash);
                return (
                    parameters.hasOwnProperty(CONSTANTS.ERROR_DESCRIPTION) ||
                    parameters.hasOwnProperty(CONSTANTS.ACCESS_TOKEN) ||
                    parameters.hasOwnProperty(CONSTANTS.ID_TOKEN)
                    );
            };


            function _getHash(hash) {
                if (hash.indexOf('#/') > -1) {
                    hash = hash.substring(hash.indexOf('#/') + 2);
                } else if (hash.indexOf('#') > -1) {
                    hash = hash.substring(1);
                }

                return hash;
            };

            function _deserialize(query) {
                var match,
                    pl = /\+/g,  // Regex for replacing addition symbol with a space
                    search = /([^&=]+)=?([^&]*)/g,
                    decode = function (s) {
                        return decodeURIComponent(s.replace(pl, ' '));
                    },
                    obj = {};
                match = search.exec(query);
                while (match) {
                    obj[decode(match[1])] = decode(match[2]);
                    match = search.exec(query);
                }

                return obj;
            };

            function getRequestInfo(hash) {
                hash = _getHash(hash);
                var parameters = _deserialize(hash);
                var requestInfo = {
                    valid: false,
                    parameters: {},
                    stateMatch: false,
                    stateResponse: '',
                    requestType: REQUEST_TYPE.UNKNOWN
                };
                if (parameters) {
                    requestInfo.parameters = parameters;
                    if (parameters.hasOwnProperty(CONSTANTS.ERROR_DESCRIPTION) ||
                        parameters.hasOwnProperty(CONSTANTS.ACCESS_TOKEN) ||
                        parameters.hasOwnProperty(CONSTANTS.ID_TOKEN)) {

                        requestInfo.valid = true;
            
                        // which call
                        var stateResponse = '';
                        if (parameters.hasOwnProperty('state')) {
                            console.debug('State: ' + parameters.state);
                            stateResponse = parameters.state;
                        } else {
                            console.debug('No state returned');
                        }

                        requestInfo.stateResponse = stateResponse;
            
                        // async calls can fire iframe and login request at the same time if developer does not use the API as expected
                        // incoming callback needs to be looked up to find the request type
                        switch (stateResponse) {
                            case _getItem(CONSTANTS.STORAGE.STATE_LOGIN):
                                requestInfo.requestType = REQUEST_TYPE.LOGIN;
                                requestInfo.stateMatch = true;
                                break;

                            case _getItem(CONSTANTS.STORAGE.STATE_IDTOKEN):
                                requestInfo.requestType = REQUEST_TYPE.ID_TOKEN;
                                _saveItem(CONSTANTS.STORAGE.STATE_IDTOKEN, '');
                                requestInfo.stateMatch = true;
                                break;
                        }
            
                        // external api requests may have many renewtoken requests for different resource
                        if (!requestInfo.stateMatch && window.parent) { // && window.parent.AuthenticationContext()
                            var statesInParentContext = window.parent.AuthenticationContext()._renewStates;
                            for (var i = 0; i < statesInParentContext.length; i++) {
                                if (statesInParentContext[i] === requestInfo.stateResponse) {
                                    requestInfo.requestType = REQUEST_TYPE.RENEW_TOKEN;
                                    requestInfo.stateMatch = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                return requestInfo;
            };

            var handleImplicitFlowCallback = function (id_token) {
                tokenService.saveToken(id_token);
                var localRedirect = $localStorage['localRedirect'];
                if (localRedirect) {
                    $location.path(localRedirect);
                    delete $localStorage['localRedirect'];
                }
                else {
                    $location.path('/');
                }
                $rootScope.$broadcast(loggedInEvent);
                return true;
            };

            var handleSilentRefreshCallback = function (newIdToken) {
                delete $localStorage['refreshRunning'];
                var currentClaims = tokenService.allClaims();
                var newClaims = tokenService.convertToClaims(newIdToken)
                if (currentClaims.exp && newClaims.exp && newClaims.exp > currentClaims.exp) {
                    tokenService.saveToken(newIdToken);
                    $rootScope.$broadcast(silentRefreshSuceededEvent);
                }
                else {
                    $rootScope.$broadcast(silentRefreshFailedEvent);
                }
            };

            var trySilentRefresh = function () {
                if ($localStorage['refreshRunning']) {
                    return;
                }
                $localStorage['refreshRunning'] = true;
                $rootScope.$broadcast(silentRefreshStartedEvent);
                var url = createLoginUrl('dummynonce', 'refresh');
                var html = "<iframe src='" + url + "' height='400' width='100%' id='oauthFrame' style='display:none;visibility:hidden;'></iframe>";
                var elem = angular.element(html);
                $document.find("body").append(elem);
                setTimeout(function () {
                    if ($localStorage['refreshRunning']) {
                        $rootScope.$broadcast(silentRefreshTimeoutEvent);
                        delete $localStorage['refreshRunning']
                    }

                    $document.find("#oauthFrame").remove();
                }, 5000);
            };

            var handleSignOutCallback = function () {
                delete $localStorage['logoutActive'];
                tokenService.clearTokens();
                $location.path('/');
                $rootScope.$broadcast(loggedOutEvent);
            };

            var tokenIsValidAt = function (date) {
                var claims = tokenService.allClaims();
                var expiresAtMSec = claims.exp * 1000;
                if (date <= expiresAtMSec) {
                    return true;
                }
                return false;
            }

            var validateExpirity = function () {
                if (!tokenService.hasToken()) return;
                if (!tokenService.hasValidToken()) return;

                var now = Date.now();

                if (!tokenIsValidAt(now + config.advanceRefresh)) {
                    $rootScope.$broadcast(tokenExpiresSoonEvent);
                    trySilentRefresh();
                }
            };

            init();

            $rootScope.$on('$locationChangeStart', locationChangeHandler);

            return {
                config: config,
                handleSignOutCallback: handleSignOutCallback,
                validateExpirity: validateExpirity,
                isAuthenticated: function () {
                    return tokenService.hasValidToken();
                },
                isAuthenticatedIn: function (milliseconds) {
                    return tokenService.hasValidToken() && tokenIsValidAt(new Date().getTime() + milliseconds);
                },
                signIn: function (localRedirect) {
                    login(localRedirect);
                },
                signOut: function () {
                    logout();
                },
                silentRefresh: function () {
                    trySilentRefresh();
                }
            };
        }];
    }]);


    /* Helpers & Polyfills */
    function parseQueryString(queryString) {
        var data = {}, pairs, pair, separatorIndex, escapedKey, escapedValue, key, value;

        if (queryString === null) {
            return data;
        }

        pairs = queryString.split("&");

        for (var i = 0; i < pairs.length; i++) {
            pair = pairs[i];
            separatorIndex = pair.indexOf("=");

            if (separatorIndex === -1) {
                escapedKey = pair;
                escapedValue = null;
            } else {
                escapedKey = pair.substr(0, separatorIndex);
                escapedValue = pair.substr(separatorIndex + 1);
            }

            key = decodeURIComponent(escapedKey);
            value = decodeURIComponent(escapedValue);

            if (key.substr(0, 1) === '/')
                key = key.substr(1);

            data[key] = value;
        }

        return data;
    };


    if (!String.prototype.endsWith) {
        String.prototype.endsWith = function (searchString, position) {
            var subjectString = this.toString();
            if (position === undefined || position > subjectString.length) {
                position = subjectString.length;
            }
            position -= searchString.length;
            var lastIndex = subjectString.indexOf(searchString, position);
            return lastIndex !== -1 && lastIndex === position;
        };
    }

    if (!String.prototype.startsWith) {
        String.prototype.startsWith = function (searchString, position) {
            position = position || 0;
            return this.lastIndexOf(searchString, position) === position;
        };
    }

})();