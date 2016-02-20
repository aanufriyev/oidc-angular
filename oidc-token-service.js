/// <reference path = "./oidc-angular.js"/>
/// <reference path = "./bower_components/angular/angular.js"/>
(function () {
   angular.module('oidc-angular').service('tokenService', ['$base64', '$localStorage', function ($base64, $localStorage) {
    var service = this;
    var padBase64 = function (base64data) {
        while (base64data.length % 4 !== 0) {
            base64data += "=";
        }
        return base64data;
    };
    service.getPayloadFromRawToken = function(raw)
    {
        var tokenParts = raw.split(".");
        return tokenParts[1];
    };
    service.deserializeClaims = function(raw) {
        var claimsBase64 = padBase64(raw);
        var claimsJson = $base64.decode(claimsBase64);

        var claims = JSON.parse(claimsJson);

        return claims;
    };
    
    service.convertToClaims = function(id_token) {
        var payload = service.getPayloadFromRawToken(id_token);
        var claims = service.deserializeClaims(payload);

        return claims;
    };
    
    service.saveToken = function (id_token) {
        $localStorage['idToken'] =  id_token;
        
        var idClaims = service.convertToClaims(id_token);
        $localStorage['cached-claims'] =  idClaims;
    };

    service.hasToken = function() {
        
        var claims = service.allClaims();
        
        if (!(claims && claims.hasOwnProperty("iat") && claims.hasOwnProperty('exp'))) {
            return false;
        }
        
        return true;
    };
    
    service.hasValidToken = function() {
        if (!this.hasToken()) return false;
        
        var claims = service.allClaims();
        
        var now = Date.now();
        var issuedAtMSec = claims.iat * 1000;
        var expiresAtMSec = claims.exp * 1000;
        var marginMSec = 1000;
        
        // Substract margin, because browser time could be a bit in the past
        if (issuedAtMSec - marginMSec > now) {
            console.log('oidc-connect: Token is not yet valid!')
            return false
        }
        
        if (expiresAtMSec < now) {
            console.log('oidc-connect: Token has expired!')
            return false;
        }
        
        return true;
    }

    service.allClaims = function() {
        var cachedClaims = $localStorage['cached-claims'];
        
        if (!cachedClaims) {
            var id_token = service.getIdToken();
            
            if (id_token) {
                var claims = service.convertToClaims(id_token);
                
                var idClaims = service.convertToClaims(id_token);
                $localStorage['cached-claims'] =  idClaims;
                
                return claims;
            }
        }
        
        return cachedClaims;
    };
    
    service.getIdToken = function() {
        return $localStorage['idToken'];
    };
    
    service.clearTokens = function() {
        delete $localStorage['cached-claims'];
        delete $localStorage['idToken'];
    }
}]);
})();