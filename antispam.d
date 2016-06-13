import std.digest.hmac;
import std.digest.sha;
import std.exception;
import std.file;
import std.json;
import std.string;
import std.stdio : toFile;

import ae.net.asockets;
import ae.net.http.client;
import ae.net.http.responseex;
import ae.net.http.server;
import ae.net.ietf.headers;
import ae.net.oauth.async;
import ae.net.oauth.common;
import ae.net.ssl.openssl;
import ae.sys.data;
import ae.sys.dataset;
import ae.sys.log;
import ae.utils.json;
import ae.utils.sini;

/// User configuration
struct Config
{
	/// UserVoice site, e.g. "example.uservoice.com"
	string site;

	/// URL base for this running instance, e.g. "http://antispam.example.com"
	/// Used for callacks.
	string urlBase;

	/// UserVoice API key
	string apiKey;

	/// UserVoice API secret
	string apiSecret;

	/// SSO key, for verifying web hook requests, as described here:
	/// https://feedback.uservoice.com/knowledgebase/articles/49266-setup-custom-web-service-hooks
	string ssoKey;

	/// Akismet key
	string akismetKey;
}
Config config;

struct Persist
{
	/// OAuth token and secret. Obtained after first run.
	string oauthToken, oauthSecret;
}
Persist persist;
enum persistFileName = "persist.json";

Logger log;

OAuthSession session;

void main()
{
	config = loadIni!Config("antispam.ini");
	log = createLogger("AntiSpam");

	if (persistFileName.exists)
	{
		persist = persistFileName.readText().jsonParse!Persist;
		session.token = persist.oauthToken;
		session.tokenSecret = persist.oauthSecret;
	}

	session.config.consumerKey = config.apiKey;
	session.config.consumerSecret = config.apiSecret;

	if (!persist.oauthSecret)
		oauthLogin();

	auto s = new HttpServer;
	s.log = createLogger("HTTP");
	s.handleRequest = (HttpRequest request, HttpServerConnection conn) {
		try
		{
			debug
			{
				log("Got request: " ~ request.resource);
				foreach (k, v; request.decodePostData())
					log("Post: " ~ k ~ "=" ~ v);
			}

			switch (request.resource)
			{
				case "/hook":
				{
					auto post = request.decodePostData();
					auto event = post["event"];

					auto dataStr = post["data"];

					auto digest = hmac!SHA256(cast(ubyte[])dataStr, cast(ubyte[])config.ssoKey).toHexString!(LetterCase.lower);

					auto signature = post["signature"];
					enforce(signature == digest, "Signature/digest mismatch! Calculated " ~ digest ~ " but received " ~ signature);

					auto data = dataStr.parseJSON();

					log("Event: " ~ event);

					switch (event)
					{
						case "new_suggestion":
						{
							Article article;
							auto suggestion = data["suggestion"];

							auto url = suggestion["url"].nullStr;
							article.site = url.split("/")[0..3].join("/") ~ "/";

							auto creator = suggestion["creator"];
							article.author = creator["name"].nullStr;
							article.email = creator["email"].nullStr;

							auto title = suggestion["title"].nullStr;
							auto text = suggestion["text"].nullStr;
							article.content = title ~ "\n\n" ~ text;

							article.referrer = suggestion["referrer"].nullStr;
							checkSpam(article,
								(bool ok, string reason)
								{
									log(format("Akismet result: %s (%s)", ok, reason));
									if (!ok)
									{
										auto site = url.split("/")[2];
										log("Deleting...");
										deleteSuggestion(site, suggestion["topic"]["id"].integer, suggestion["id"].integer);
									}
								});
							break;
						}
						default:
							break;
					}
					break;
				}
				case "/callback":
				break;
				default:
				throw new Exception("Unknown resource");
			}

			auto response = new HttpResponseEx;
			conn.sendResponse(response.serveText("OK"));
		}
		catch (Exception e)
		{
			log("Error with request to " ~ request.resource ~ ": " ~ e.msg);
			throw e;
		}
	};
	s.listen(12345);

	socketManager.loop();
}

string nullStr(JSONValue v)
{
	if (v.type == JSON_TYPE.NULL)
		return null;
	else
		return v.str;
}

void oauthLogin()
{
	auto request = new HttpRequest("https://" ~ config.site ~ "/api/v1/oauth/request_token.json");
	// ?oauth_callback=" ~ encodeUrlParameter(config.urlBase ~ "/callback)
	prepareRequest(session, request);
	httpRequest(request,
		(HttpResponse response, string disconnectReason)
		{
			enforce(response.status == HttpStatusCode.OK);
			auto responseText = cast(string)response.getContent().toHeap;
			log(responseText);
			auto json = responseText.parseJSON();
			session.token = json["token"]["oauth_token"].nullStr;
			session.tokenSecret = json["token"]["oauth_token_secret"].nullStr;

			{
				import std.stdio;
				auto authUrl = "https://" ~ config.site ~ "/oauth/authorize?oauth_token=" ~ session.token;
				writeln("Please visit " ~ authUrl);
				writeln("Log in at the URL, and press Enter to continue the program");

				// auto authResponse = readln().strip().decodeUrlParameters();
				readln();
			}

			request = new HttpRequest("https://" ~ config.site ~ "/api/v1/oauth/access_token.json");
			// ?oauth_verifier=" ~ encodeUrlParameter(config.oauthVerifier.length)
			prepareRequest(session, request);
			httpRequest(request,
				(HttpResponse response, string disconnectReason)
				{
					enforce(response.status == HttpStatusCode.OK);
					auto responseText = cast(string)response.getContent().toHeap;
					log(responseText);
					auto json = responseText.parseJSON();
					session.token = json["token"]["oauth_token"].nullStr;
					session.tokenSecret = json["token"]["oauth_token_secret"].nullStr;

					persist.oauthToken = session.token;
					persist.oauthSecret = session.tokenSecret;
					persist.toJson().toFile(persistFileName);
				});
		});
}

void deleteSuggestion(string site, long forumID, long suggestionID)
{
	auto request = new HttpRequest(format("https://%s/api/v1/forums/%d/suggestions/%d.json", site, forumID, suggestionID));
	request.method = "DELETE";
	prepareRequest(session, request);
	httpRequest(request,
		(HttpResponse response, string disconnectReason)
		{
			enforce(response.status == HttpStatusCode.OK);
			auto responseText = cast(string)response.getContent().toHeap;
			log("Delete result: " ~ responseText);
		});
}

struct Article
{
	string site;
	string author;
	string email;
	string content;
	string referrer;
}

void checkSpam(Article article, void delegate(bool ok, string reason) handler)
{
	debug if (article.content.indexOf("spam-test-123") >= 0)
		return handler(false, "Test keyword matched");

	string[string] params = [
		"blog"                 : article.site,
		"user_ip"              : "127.0.0.1",
		"user_agent"           : "",
		"referrer"             : article.referrer,
		"comment_author"       : article.author,
		"comment_author_email" : article.email,
		"comment_content"      : article.content,
	];

	httpPost("http://" ~ config.akismetKey ~ ".rest.akismet.com/1.1/comment-check", UrlParameters(params), (string result) {
		if (result == "false")
			handler(true, null);
		else
		if (result == "true")
			handler(false, "Akismet thinks your post looks like spam");
		else
			handler(false, "Akismet error: " ~ result);
	}, (string error) {
		handler(false, "Akismet error: " ~ error);
	});
}
