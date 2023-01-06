#region License

// The MIT License
//
// Copyright (c) 2006-2008 DevDefined Limited.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#endregion

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using QueryParameter = System.Collections.Generic.KeyValuePair<string, string>;

namespace DevDefined.OAuth.Framework;

[Serializable]
public class OAuthContext : IOAuthContext
{
	private readonly BoundParameter _bodyHash;
	private readonly BoundParameter _callbackUrl;
	private readonly BoundParameter _consumerKey;
	private readonly BoundParameter _nonce;
	private readonly BoundParameter _sessionHandle;
	private readonly BoundParameter _signature;
	private readonly BoundParameter _signatureMethod;
	private readonly BoundParameter _timestamp;
	private readonly BoundParameter _token;
	private readonly BoundParameter _tokenSecret;
	private readonly BoundParameter _verifier;
	private readonly BoundParameter _version;
	private readonly BoundParameter _xAuthMode;
	private readonly BoundParameter _xAuthUsername;
	private readonly BoundParameter _xAuthPassword;
	private NameValueCollection _authorizationHeaderParameters;
	private NameValueCollection _cookies;
	private NameValueCollection _formEncodedParameters;
	private NameValueCollection _headers;
	private NameValueCollection _queryParameters;
	private Uri _rawUri;

	public OAuthContext()
	{
		_verifier = new BoundParameter(Parameters.OAuth_Verifier, this);
		_consumerKey = new BoundParameter(Parameters.OAuth_Consumer_Key, this);
		_callbackUrl = new BoundParameter(Parameters.OAuth_Callback, this);
		_nonce = new BoundParameter(Parameters.OAuth_Nonce, this);
		_signature = new BoundParameter(Parameters.OAuth_Signature, this);
		_signatureMethod = new BoundParameter(Parameters.OAuth_Signature_Method, this);
		_timestamp = new BoundParameter(Parameters.OAuth_Timestamp, this);
		_token = new BoundParameter(Parameters.OAuth_Token, this);
		_tokenSecret = new BoundParameter(Parameters.OAuth_Token_Secret, this);
		_version = new BoundParameter(Parameters.OAuth_Version, this);
		_sessionHandle = new BoundParameter(Parameters.OAuth_Session_Handle, this);
		_bodyHash = new BoundParameter(Parameters.OAuth_Body_Hash, this);

		_xAuthUsername = new BoundParameter(Parameters.XAuthUsername, this);
		_xAuthPassword = new BoundParameter(Parameters.XAuthPassword, this);
		_xAuthMode = new BoundParameter(Parameters.XAuthMode, this);

		FormEncodedParameters = new NameValueCollection();
		Cookies = new NameValueCollection();
		Headers = new NameValueCollection();
		AuthorizationHeaderParameters = new NameValueCollection();
	}

	public NameValueCollection Headers
	{
		get
		{
			if (_headers == null) _headers = new NameValueCollection();
			return _headers;
		}
		set => _headers = value;
	}

	public NameValueCollection QueryParameters
	{
		get
		{
			if (_queryParameters == null) _queryParameters = new NameValueCollection();
			return _queryParameters;
		}
		set => _queryParameters = value;
	}

	public NameValueCollection Cookies
	{
		get
		{
			if (_cookies == null) _cookies = new NameValueCollection();
			return _cookies;
		}
		set => _cookies = value;
	}

	public NameValueCollection FormEncodedParameters
	{
		get
		{
			if (_formEncodedParameters == null) _formEncodedParameters = new NameValueCollection();
			return _formEncodedParameters;
		}
		set => _formEncodedParameters = value;
	}

	public NameValueCollection AuthorizationHeaderParameters
	{
		get
		{
			if (_authorizationHeaderParameters == null) _authorizationHeaderParameters = new NameValueCollection();
			return _authorizationHeaderParameters;
		}
		set => _authorizationHeaderParameters = value;
	}

	public byte[] RawContent { get; set; }
	public string RawContentType { get; set; }

	public Uri RawUri
	{
		get => _rawUri;
		set
		{
			_rawUri = value;

			var newParameters = HttpUtility.ParseQueryString(_rawUri.Query);

			// TODO: tidy this up, bit clunky

			foreach (string parameter in newParameters)
			{
				QueryParameters[parameter] = newParameters[parameter];
			}

			NormalizedRequestUrl = UriUtility.NormalizeUri(_rawUri);
		}
	}

	public string NormalizedRequestUrl { get; private set; }

	public string RequestMethod { get; set; }

	public bool IncludeOAuthRequestBodyHashInSignature { get; set; }

	public string Nonce
	{
		get => _nonce.Value;
		set => _nonce.Value = value;
	}

	public string Verifier
	{
		get => _verifier.Value;
		set => _verifier.Value = value;
	}

	public string SessionHandle
	{
		get => _sessionHandle.Value;
		set => _sessionHandle.Value = value;
	}

	public string CallbackUrl
	{
		get => _callbackUrl.Value;
		set => _callbackUrl.Value = value;
	}

	public string Signature
	{
		get => _signature.Value;
		set => _signature.Value = value;
	}

	public string SignatureMethod
	{
		get => _signatureMethod.Value;
		set => _signatureMethod.Value = value;
	}

	public string Timestamp
	{
		get => _timestamp.Value;
		set => _timestamp.Value = value;
	}

	public string BodyHash
	{
		get => _bodyHash.Value;
		set => _bodyHash.Value = value;
	}

	public string Version
	{
		get => _version.Value;
		set => _version.Value = value;
	}

	public bool UseAuthorizationHeader { get; set; }

	public string Realm
	{
		get => AuthorizationHeaderParameters[Parameters.Realm];
		set => AuthorizationHeaderParameters[Parameters.Realm] = value;
	}

	public string ConsumerKey
	{
		get => _consumerKey.Value;
		set => _consumerKey.Value = value;
	}

	public string Token
	{
		get => _token.Value;
		set => _token.Value = value;
	}

	public string TokenSecret
	{
		get => _tokenSecret.Value;
		set => _tokenSecret.Value = value;
	}

	public string XAuthMode
	{
		get => _xAuthMode.Value;
		set => _xAuthMode.Value = value;
	}

	public string XAuthUsername
	{
		get => _xAuthUsername.Value;
		set => _xAuthUsername.Value = value;
	}

	public string XAuthPassword
	{
		get => _xAuthPassword.Value;
		set => _xAuthPassword.Value = value;
	}

	public Uri GenerateUri()
	{
		var builder = new UriBuilder(NormalizedRequestUrl);

		var parameters = QueryParameters.ToQueryParametersExcludingTokenSecret();

		builder.Query = UriUtility.FormatQueryString(parameters);

		return builder.Uri;
	}

	public string GenerateUrl()
	{
		var builder = new UriBuilder(NormalizedRequestUrl);

		builder.Query = "";

		return builder.Uri + "?" + UriUtility.FormatQueryString(QueryParameters);
	}

	public string GenerateOAuthParametersForHeader()
	{
		var builder = new StringBuilder();

		if (Realm != null) builder.Append("realm=\"").Append(Realm).Append("\"");

		var parameters =
			AuthorizationHeaderParameters.ToQueryParametersExcludingTokenSecret();

		foreach (
			var parameter in parameters.Where(p => p.Key != Parameters.Realm)
		)
		{
			if (builder.Length > 0) builder.Append(",");
			builder.Append(UriUtility.UrlEncode(parameter.Key)).Append("=\"").Append(
				UriUtility.UrlEncode(parameter.Value)).Append("\"");
		}

		builder.Insert(0, "OAuth ");

		return builder.ToString();
	}

	public Uri GenerateUriWithoutOAuthParameters()
	{
		var builder = new UriBuilder(NormalizedRequestUrl);

		var parameters = QueryParameters.ToQueryParameters()
			.Where(q => !q.Key.StartsWith(Parameters.OAuthParameterPrefix) &&
			            !q.Key.StartsWith(Parameters.XAuthParameterPrefix));

		builder.Query = UriUtility.FormatQueryString(parameters);

		return builder.Uri;
	}

	public void GenerateAndSetBodyHash()
	{
		BodyHash = GenerateBodyHash();
	}

	public string GenerateBodyHash()
	{
		var hash = SHA1.Create().ComputeHash((RawContent ?? new byte[0]));
		return Convert.ToBase64String(hash);
	}

	public string GenerateSignatureBase()
	{
		if (string.IsNullOrEmpty(ConsumerKey))
		{
			throw Error.MissingRequiredOAuthParameter(this, Parameters.OAuth_Consumer_Key);
		}

		if (string.IsNullOrEmpty(SignatureMethod))
		{
			throw Error.MissingRequiredOAuthParameter(this, Parameters.OAuth_Signature_Method);
		}

		if (string.IsNullOrEmpty(RequestMethod))
		{
			throw Error.RequestMethodHasNotBeenAssigned("RequestMethod");
		}

		if (IncludeOAuthRequestBodyHashInSignature)
		{
			GenerateAndSetBodyHash();
		}

		var allParameters = new List<QueryParameter>();

		//fix for issue: http://groups.google.com/group/oauth/browse_thread/thread/42ef5fecc54a7e9a/a54e92b13888056c?hl=en&lnk=gst&q=Signing+PUT+Request#a54e92b13888056c
		if (FormEncodedParameters != null && RequestMethod == "POST")
			allParameters.AddRange(FormEncodedParameters.ToQueryParametersExcludingTokenSecret());

		if (QueryParameters != null)
			allParameters.AddRange(QueryParameters.ToQueryParametersExcludingTokenSecret());

		if (Cookies != null) allParameters.AddRange(Cookies.ToQueryParametersExcludingTokenSecret());

		if (AuthorizationHeaderParameters != null)
			allParameters.AddRange(AuthorizationHeaderParameters.ToQueryParametersExcludingTokenSecret()
				.Where(q => q.Key != Parameters.Realm));

		allParameters.RemoveAll(param => param.Key == Parameters.OAuth_Signature);

		var signatureBase =
			UriUtility.FormatParameters(RequestMethod, new Uri(NormalizedRequestUrl), allParameters);

		return signatureBase;
	}
}