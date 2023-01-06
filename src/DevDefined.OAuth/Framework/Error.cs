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
using System.IO;
using System.Net;
using DevDefined.OAuth.Provider;

namespace DevDefined.OAuth.Framework;

public static class Error
{
    public static Exception MissingRequiredOAuthParameter(IOAuthContext context, string parameterName)
    {
        var exception = new OAuthException(context, OAuthProblems.ParameterAbsent,
            $"Missing required parameter : {parameterName}");

        exception.Report.ParametersAbsent.Add(parameterName);

        return exception;
    }

    public static Exception OAuthAuthenticationFailure(string errorMessage)
    {
        return new Exception($"OAuth authentication failed, message was: {errorMessage}");
    }

    public static Exception TokenCanNoLongerBeUsed(string token)
    {
        return new Exception($"Token \"{token}\" is no longer valid");
    }

    public static Exception FailedToParseResponse(string parameters)
    {
        return new Exception($"Failed to parse response string \"{parameters}\"");
    }

    public static Exception UnknownSignatureMethod(string signatureMethod)
    {
        return new Exception($"Unknown signature method \"{signatureMethod}\"");
    }

    public static Exception ForRsaSha1SignatureMethodYouMustSupplyAssymetricKeyParameter()
    {
        return
            new Exception(
                "For the RSASSA-PKCS1-v1_5 signature method you must use the constructor which takes an additional AssymetricAlgorithm \"key\" parameter");
    }

    public static Exception RequestFailed(WebException innerException)
    {
        var response = innerException.Response as HttpWebResponse;

        if (response != null)
        {
            using var reader = new StreamReader(innerException.Response.GetResponseStream());

            var body = reader.ReadToEnd();

            return
                new Exception(
                    $"Request for uri: {response.ResponseUri} failed.\r\nstatus code: {response.StatusCode}\r\nheaders: {response.Headers}\r\nbody:\r\n{body}", innerException);
        }

        return innerException;
    }

    public static Exception EmptyConsumerKey()
    {
        throw new Exception("Consumer key is null or empty");
    }

    public static Exception RequestMethodHasNotBeenAssigned(string parameter)
    {
        return new Exception($"The RequestMethod parameter \"{parameter}\" is null or empty.");
    }

    public static Exception FailedToValidateSignature(IOAuthContext context)
    {
        return new OAuthException(context, OAuthProblems.SignatureInvalid, "Failed to validate signature");
    }

    public static Exception FailedToValidateBodyHash(IOAuthContext context)
    {
        return new OAuthException(context, OAuthProblems.BodyHashInvalid, "Failed to validate body hash");
    }

    public static Exception UnknownConsumerKey(IOAuthContext context)
    {
        return new OAuthException(context, OAuthProblems.ConsumerKeyUnknown,
            $"Unknown Consumer (Realm: {context.Realm}, Key: {context.ConsumerKey})");
    }

    public static Exception AlgorithmPropertyNotSetOnSigningContext()
    {
        return
            new Exception(
                "Algorithm Property must be set on SingingContext when using an Assymetric encryption method such as RSA-SHA1");
    }

    public static Exception SuppliedTokenWasNotIssuedToThisConsumer(string expectedConsumerKey,
        string actualConsumerKey)
    {
        return
            new Exception(
                $"Supplied token was not issued to this consumer, expected key: {expectedConsumerKey}, actual key: {actualConsumerKey}");
    }

    public static Exception AccessDeniedToProtectedResource(AccessOutcome outcome)
    {
        var uri = outcome.Context.GenerateUri();

        if (string.IsNullOrEmpty(outcome.AdditionalInfo))
        {
            return new AccessDeniedException(outcome, $"Access to resource \"{uri}\" was denied");
        }

        return new AccessDeniedException(outcome,
            $"Access to resource: {uri} was denied, additional info: {outcome.AdditionalInfo}");
    }

    public static Exception ConsumerHasNotBeenGrantedAccessYet(IOAuthContext context)
    {
        return new OAuthException(context, OAuthProblems.PermissionUnknown,
            "The decision to give access to the consumer has yet to be made, please try again later.");
    }

    public static Exception ConsumerHasBeenDeniedAccess(IOAuthContext context)
    {
        return new OAuthException(context, OAuthProblems.PermissionDenied,
            "The consumer was denied access to this resource.");
    }

    public static Exception CantBuildProblemReportWhenProblemEmpty()
    {
        return new Exception("Can't build problem report when \"Problem\" property is null or empty");
    }

    public static Exception NonceHasAlreadyBeenUsed(IOAuthContext context)
    {
        return new OAuthException(context, OAuthProblems.NonceUsed,
            $"The nonce value \"{context.Nonce}\" has already been used");
    }

    public static Exception ThisConsumerRequestHasAlreadyBeenSigned()
    {
        return new Exception("The consumer request for consumer \"{0}\" has already been signed");
    }

    public static Exception CallbackWasNotConfirmed()
    {
        return new Exception("Callback was not confirmed");
    }

    public static Exception RejectedRequiredOAuthParameter(IOAuthContext context, string parameter)
    {
        return new OAuthException(context, OAuthProblems.ParameterRejected, $"The parameter \"{parameter}\" was rejected");
    }

    public static Exception UnknownToken(IOAuthContext context, string token)
    {
        return new OAuthException(context, OAuthProblems.TokenRejected, $"Unknown or previously rejected token \"{token}\"");
    }

    public static Exception UnknownToken(IOAuthContext context, string token, Exception exception)
    {
        return new OAuthException(context, OAuthProblems.TokenRejected, $"Unknown or previously rejected token \"{token}\"", exception);
    }

    public static Exception RequestForTokenMustNotIncludeTokenInContext(IOAuthContext context)
    {
        throw new OAuthException(context, OAuthProblems.ParameterRejected, "When obtaining a request token, you must not supply the oauth_token parameter");
    }

    public static Exception ExperiencingIssueWithCreatingUriDueToMissingAppConfig(ArgumentNullException argumentException)
    {
        return
            new Exception(
                "It appears this may be the first Uri constructed by this AppDomain, and you have no App.config or Web.config file - which has triggered an unusual edge case: see this blog post from more details - http://ayende.com/Blog/archive/2010/03/04/is-select-system.uri-broken.aspx",
                argumentException);
    }

    public static Exception EncounteredUnexpectedBodyHashInFormEncodedRequest(IOAuthContext context)
    {
        throw new OAuthException(context, OAuthProblems.ParameterRejected, "Encountered unexpected oauth_body_hash value in form-encoded request");
    }

    public static Exception EmptyXAuthMode(IOAuthContext context)
    {
        throw new OAuthException(context, OAuthProblems.ParameterAbsent, "The x_auth_mode parameter must be present");
    }

    public static Exception InvalidXAuthMode(IOAuthContext context)
    {
        throw new OAuthException(context, OAuthProblems.ParameterRejected, "The x_auth_mode parameter is invalid");
    }

    public static Exception EmptyXAuthUsername(IOAuthContext context)
    {
        throw new OAuthException(context, OAuthProblems.ParameterAbsent, "The x_auth_username parameter must be present");
    }

    public static Exception EmptyXAuthPassword(IOAuthContext context)
    {
        throw new OAuthException(context, OAuthProblems.ParameterAbsent, "The x_auth_password parameter must be present");
    }

    public static Exception FailedXAuthAuthentication(IOAuthContext context)
    {
        throw new OAuthException(context, OAuthProblems.ParameterRejected, "Authentication failed with the specified username and password");
    }
}