# PAM authentification plugin for MediaWiki

This plugin will provide authentification against both MediaWiki users and system users using PAM.

MediaWiki authentication works because of MediaWiki's default fallback behaviour. If a user doesn't exist in PAM, it autotically tries to 
authenticate against its own users. This is accomplished by returning false on ->strict().
