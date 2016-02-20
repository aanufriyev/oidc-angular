/// <reference path = "./oidc-angular.js"/>
/// <reference path = "./bower_components/angular/angular.js"/>
(function () {
    angular.module('oidc-angular').factory('oidcHttpInterceptor', ['$rootScope', '$q', '$auth', 'tokenService', 'oidcEvents', function ($rootScope, $q, $auth, tokenService, oidcEvents) {
        return {
            'request': function (request) {
                if (request.url.startsWith($auth.config.apiUrl)) {
                    var appendBearer = false;
                    if ($auth.config.enableRequestChecks) {
                        if (tokenService.hasToken()) { // Only append token when it's valid.
                            if (tokenService.hasValidToken()) {
                                appendBearer = true;
                            }
                            else {
                                $rootScope.$broadcast(oidcEvents.tokenExpiredEvent, { request: request });
                            }
                        }
                        else {
                            $rootScope.$broadcast(oidcEvents.tokenMissingEvent, { request: request });
                        }
                    }
                    else {
                        appendBearer = tokenService.hasValidToken();
                    }

                    if (appendBearer) {
                        var token = tokenService.getIdToken();
                        request.headers['Authorization'] = 'Bearer ' + token;
                    }
                }
          
                // do something on success
                return request;
            },

            'response': function (response) {
                // Proactively check if the token will expire soon
                $auth.validateExpirity();

                return response;
            },

            'responseError': function (response) {
                if (response.status == 401) {
                    if (!tokenService.hasToken()) { // There was probably no token attached, because there is none
                        $rootScope.$broadcast(oidcEvents.tokenMissingEvent, { response: response });
                    }
                    else if (!tokenService.hasValidToken()) { // Seems the token is not valid anymore
                        $rootScope.$broadcast(oidcEvents.tokenExpiredEvent, { response: response });
                    }
                    else { // any other
                        $rootScope.$broadcast(oidcEvents.unauthorizedEvent, { response: response });
                    }
                }

                return $q.reject(response);
            }
        };
    }]);
})();