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
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using System.Web;

namespace DevDefined.OAuth.Framework
{
	public class OAuthContextBuilder : IOAuthContextBuilder
	{
		readonly Func<Uri, Uri> _uriAdjuster;
		readonly Func<Uri, Uri> _emptyUriAdjuster = (uri) => uri;

		public OAuthContextBuilder(Func<Uri, Uri> uriAdjuster)
		{
			_uriAdjuster = uriAdjuster ?? _emptyUriAdjuster;
		}

		public OAuthContextBuilder()
			: this(null)
		{
		}

		public virtual IOAuthContext FromUrl(string httpMethod, string url)
		{
			if (string.IsNullOrEmpty(url)) throw new ArgumentNullException("url");

			Uri uri;

			if (!Uri.TryCreate(url, UriKind.RelativeOrAbsolute, out uri))
			{
				throw new ArgumentException(string.Format("Failed to parse url: {0} into a valid Uri instance", url));
			}

			return FromUri(httpMethod, uri);
		}

		public virtual IOAuthContext FromUri(string httpMethod, Uri uri)
		{
			uri = CleanUri(uri);

			if (httpMethod == null) throw new ArgumentNullException("httpMethod");
			if (uri == null) throw new ArgumentNullException("uri");

			return new OAuthContext
			{
				RawUri = CleanUri(uri),
				RequestMethod = httpMethod
			};
		}

		public virtual IOAuthContext FromHttpRequest(HttpRequestMessage request)
		{
			var context = new OAuthContext
			{
				RawUri = CleanUri(request.RequestUri),
				Cookies = CollectCookies(request),
				Headers = GetCleanedNameValueCollection(request.Headers),
				RequestMethod = request.Method.Method,
				FormEncodedParameters = new NameValueCollection(), // HttpRequest.Form does not migrate cleanly to .NET Core
				QueryParameters = HttpUtility.ParseQueryString(request.RequestUri.Query),
			};

			var rawContent = request.Content.ReadAsByteArrayAsync().Result;
			if (rawContent.Length > 0) { context.RawContent = rawContent; }

			ParseAuthorizationHeader(request.Headers, context);

			return context;
		}

		public virtual IOAuthContext FromWebRequest(HttpWebRequest request, Stream rawBody)
		{
			using (var reader = new StreamReader(rawBody))
			{
				return FromWebRequest(request, reader.ReadToEnd());
			}
		}

		public virtual IOAuthContext FromWebRequest(HttpWebRequest request, string body)
		{
			var context = new OAuthContext
			{
				RawUri = CleanUri(request.RequestUri),
				Cookies = CollectCookies(request),
				Headers = request.Headers,
				RequestMethod = request.Method
			};

			string contentType = request.Headers[HttpRequestHeader.ContentType] ?? string.Empty;

			if (contentType.ToLower().Contains("application/x-www-form-urlencoded"))
			{
				context.FormEncodedParameters = HttpUtility.ParseQueryString(body);
			}

			ParseAuthorizationHeader(request.Headers, context);

			return context;
		}

		protected virtual NameValueCollection GetCleanedNameValueCollection(HttpRequestHeaders headers)
		{
			var nvc = new NameValueCollection();

			foreach (var header in headers)
			{
				nvc.Add(header.Key, string.Join(";", header.Value));
			}

			return nvc;
		}

		protected virtual NameValueCollection GetCleanedNameValueCollection(NameValueCollection requestQueryString)
		{
			var nvc = new NameValueCollection(requestQueryString);

			if (nvc.HasKeys())
			{
				nvc.Remove(null);
			}

			return nvc;
		}

		protected virtual Uri CleanUri(Uri uri)
		{
			var adjustedUri = _uriAdjuster(uri);
			return RemoveEmptyQueryStringParameterIntroducedBySomeOpenSocialPlatformImplementations(adjustedUri);
		}

		static Uri RemoveEmptyQueryStringParameterIntroducedBySomeOpenSocialPlatformImplementations(Uri adjustedUri)
		{
			// this is a fix for OpenSocial platforms sometimes appending an empty query string parameter
			// to their url.

			string originalUrl = adjustedUri.OriginalString;
			return originalUrl.EndsWith("&") ? new Uri(originalUrl.Substring(0, originalUrl.Length - 1)) : adjustedUri;
		}

		protected virtual NameValueCollection CollectCookies(WebRequest request)
		{
			return CollectCookiesFromHeaderString(request.Headers[HttpRequestHeader.Cookie]);
		}

		protected virtual NameValueCollection CollectCookies(HttpRequestMessage request)
		{
			return CollectCookiesFromHeaderString(request.Headers.GetValues("Set-Cookie").FirstOrDefault());
		}

		protected virtual NameValueCollection CollectCookiesFromHeaderString(string cookieHeader)
		{
			var cookieCollection = new NameValueCollection();

			if (!string.IsNullOrEmpty(cookieHeader))
			{
				string[] cookies = cookieHeader.Split(';');
				foreach (string cookie in cookies)
				{
					//Remove the trailing and Leading white spaces
					string strCookie = cookie.Trim();

					var reg = new Regex(@"^(\S*)=(\S*)$");
					if (reg.IsMatch(strCookie))
					{
						Match match = reg.Match(strCookie);
						if (match.Groups.Count > 2)
						{
							cookieCollection.Add(match.Groups[1].Value,
								HttpUtility.UrlDecode(match.Groups[2].Value).Replace(' ', '+'));
							//HACK: find out why + is coming in as " "
						}
					}
				}
			}

			return cookieCollection;
		}
		
		protected virtual void ParseAuthorizationHeader(NameValueCollection headers, OAuthContext context)
		{
			var authHeader = headers["Authorization"];
			if (string.IsNullOrEmpty(authHeader)) return;
			context.AuthorizationHeaderParameters = UriUtility
				.GetHeaderParameters(authHeader).ToNameValueCollection();
			context.UseAuthorizationHeader = true;
		}

		protected virtual void ParseAuthorizationHeader(HttpRequestHeaders headers, OAuthContext context)
		{
			var authHeader = headers.GetValues("Authorization").FirstOrDefault();
			if (string.IsNullOrEmpty(authHeader)) return;
			context.AuthorizationHeaderParameters = UriUtility
				.GetHeaderParameters(authHeader).ToNameValueCollection();
			context.UseAuthorizationHeader = true;
		}
	}
}