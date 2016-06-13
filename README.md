UserVoice anti-spam
===================

This is a spam filter for UserVoice, since their free-tier spam filter
is ... not great.

Usage
-----

1. Create a UserVoice API key
2. Create a UserVoice web hook, pointing to
   http://url-where-this-service-is-running/hook
3. Configure this service (copy `antispam.ini.sample` to
   `antispam.ini` and edit accordingly)
4. Run the service. On the first launch, you will be given an URL to
   authorize a token, so the service can act on your behalf. (Only
   users can delete suggestions.)
5. Once the service is authorized, it can continue running as a
   daemon.
