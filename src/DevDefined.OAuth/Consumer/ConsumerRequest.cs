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
using System.Net;
using System.Web;
using System.Xml.Linq;
using DevDefined.OAuth.Framework;
using DevDefined.OAuth.Utility;

namespace DevDefined.OAuth.Consumer;

public class ConsumerRequest : IConsumerRequest
{
	private readonly IToken _token;

	public ConsumerRequest(IOAuthContext context, IOAuthConsumerContext consumerContext, IToken token)
	{
		Context = context ?? throw new ArgumentNullException(nameof(context));
		ConsumerContext = consumerContext ?? throw new ArgumentNullException(nameof(consumerContext));
		_token = token;
	}

	private string ResponseBody { get; set; }

	public IOAuthConsumerContext ConsumerContext { get; }

	public IOAuthContext Context { get; }

	public XDocument ToDocument()
	{
		return XDocument.Parse(ToString());
	}

	public byte[] ToBytes()
	{
		return Convert.FromBase64String(ToString());
	}

	public RequestDescription GetRequestDescription()
	{
		if (string.IsNullOrEmpty(Context.Signature))
		{
			if (_token != null)
			{
				ConsumerContext.SignContextWithToken(Context, _token);
			}
			else
			{
				ConsumerContext.SignContext(Context);
			}
		}

		var uri = Context.GenerateUri();

		var description = new RequestDescription
		{
			Url = uri,
			Method = Context.RequestMethod,
		};

		if (Context.FormEncodedParameters is { Count: > 0 })
		{
			description.ContentType = Parameters.HttpFormEncoded;
			description.Body = UriUtility.FormatQueryString(Context.FormEncodedParameters.ToQueryParametersExcludingTokenSecret());
		}
		else if (!string.IsNullOrEmpty(RequestBody))
		{
			description.Body = UriUtility.UrlEncode(RequestBody);
		}

		else if (Context.RawContent != null)
		{
			description.ContentType = Context.RawContentType;
			description.RawBody = Context.RawContent;
		}

		if (Context.Headers != null)
		{
			description.Headers.Add(Context.Headers);
		}

		if (ConsumerContext.UseHeaderForOAuthParameters)
		{
			description.Headers[Parameters.OAuth_Authorization_Header] = Context.GenerateOAuthParametersForHeader();
		}

		return description;
	}

	public HttpWebResponse ToWebResponse()
	{
		try
		{
			var request = ToWebRequest();
			return (HttpWebResponse) request.GetResponse();
		}
		catch (WebException webEx)
		{
			if (WebExceptionHelper.TryWrapException(Context, webEx, out var authException, ResponseBodyAction))
			{
				throw authException;
			}

			throw;
		}
	}

	public NameValueCollection ToBodyParameters()
	{
		try
		{
			var encodedFormParameters = ToString();

			ResponseBodyAction?.Invoke(encodedFormParameters);

			try
			{
				return HttpUtility.ParseQueryString(encodedFormParameters);
			}
			catch (ArgumentNullException)
			{
				throw Error.FailedToParseResponse(encodedFormParameters);
			}
		}
		catch (WebException webEx)
		{
			throw Error.RequestFailed(webEx);
		}
	}

	public IConsumerRequest SignWithoutToken()
	{
		EnsureRequestHasNotBeenSignedYet();
		ConsumerContext.SignContext(Context);
		return this;
	}

	public IConsumerRequest SignWithToken()
	{
		return SignWithToken(_token);
	}

	public IConsumerRequest SignWithToken(IToken token)
	{
		EnsureRequestHasNotBeenSignedYet();
		ConsumerContext.SignContextWithToken(Context, token);
		return this;
	}

	public Uri ProxyServerUri { get; set; }

	public Action<string> ResponseBodyAction { get; set; }

	public string AcceptsType { get; set; }

	/// <summary>
	/// Override the default request timeout in milliseconds.
	/// Sets the <see cref="System.Net.HttpWebRequest.Timeout"/> property.
	/// </summary>
	public int? Timeout { get; set; }

	public string RequestBody { get; set; }

	public virtual HttpWebRequest ToWebRequest()
	{
		var description = GetRequestDescription();

		var request = (HttpWebRequest) WebRequest.Create(description.Url);
		request.Method = description.Method;
		request.UserAgent = ConsumerContext.UserAgent;

		if (Timeout.HasValue)
			request.Timeout = Timeout.Value;

		if (!string.IsNullOrEmpty(AcceptsType))
		{
			request.Accept = AcceptsType;
		}

		try
		{
			if (Context.Headers["If-Modified-Since"] != null)
			{
				var modifiedDateString = Context.Headers["If-Modified-Since"];
				request.IfModifiedSince = DateTime.Parse(modifiedDateString);
			}
		}
		catch (Exception ex)
		{
			throw new ApplicationException("If-Modified-Since header could not be parsed as a datetime", ex);
		}

		if (ProxyServerUri != null)
		{
			request.Proxy = new WebProxy(ProxyServerUri, false);
		}
			
		if (description.Headers.Count > 0)
		{
			foreach (var key in description.Headers.AllKeys)
			{
				request.Headers[key] = description.Headers[key];
			}
		}

		if (!string.IsNullOrEmpty(description.Body))
		{
			request.ContentType = description.ContentType;

			using var writer = new StreamWriter(request.GetRequestStream());

			writer.Write(description.Body);
		}
		else if (description.RawBody is { Length: > 0 })
		{
			request.ContentType = description.ContentType;

			using var writer = new BinaryWriter(request.GetRequestStream());

			writer.Write(description.RawBody);
		}

		return request;
	}

	public override string ToString()
	{
		if (string.IsNullOrEmpty(ResponseBody))
		{
			ResponseBody = ToWebResponse().ReadToEnd();
		}

		return ResponseBody;
	}

	private void EnsureRequestHasNotBeenSignedYet()
	{
		if (!string.IsNullOrEmpty(Context.Signature))
		{
			throw Error.ThisConsumerRequestHasAlreadyBeenSigned();
		}
	}
}