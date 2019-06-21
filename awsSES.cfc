component {

	function init(
		required string accessKeyId= this.accessKeyId
	,	required string secretAccessKey= this.secretAccessKey
	,	string throttle= "auto"
	,	string defaultCharSet= "UTF-8"
	,	string defaultFailTo= ""
	,	string endPoint= "https://email.us-east-1.amazonaws.com"
	,	numeric httpTimeOut= 120
	,	boolean debug
	) {
		this.defaultCharSet= arguments.defaultCharSet;
		this.defaultFailTo= arguments.defaultFailTo;
		this.accessKeyId= arguments.accessKeyId;
		this.secretAccessKey= arguments.secretAccessKey;
		this.endPoint= arguments.endPoint;
		this.httpTimeOut= arguments.httpTimeOut;
		this.debug= ( arguments.debug ?: request.debug ?: false );
		this.lastSend= 0;
		this.throttleDelay= 0;
		this.offSet= getTimeZoneInfo().utcTotalOffset;
		this.setThrottle( arguments.throttle );
		return this;
	}

	numeric function setThrottle( required string throttle= "auto" ) {
		var check= 0;
		var limit= 0;
		this.throttleDelay= 0;
		if ( isNumeric( arguments.throttle ) ) {
			this.throttleDelay= arguments.throttle;
		} else {
			// auto 
			check= GetSendQuota();
			if ( check.success && check.MaxSendRate > 0 ) {
				this.throttleDelay= ( ( 1 / check.MaxSendRate ) * 1000 ) - 100;
			}
		}
		return limit;
	}

	/**
	 * @description NSA SHA256 Algorithm
	 */
	binary function HMAC_SHA256( required string signKey, required string signMessage ) {
		var jMsg= JavaCast( "string", arguments.signMessage ).getBytes( "iso-8859-1" );
		var jKey= JavaCast( "string", arguments.signKey ).getBytes( "iso-8859-1" );
		var key= createObject( "java", "javax.crypto.spec.SecretKeySpec" );
		var mac= createObject( "java", "javax.crypto.Mac" );
		key= key.init( jKey, "HmacSHA256" );
		mac= mac.getInstance( key.getAlgorithm() );
		mac.init( key );
		mac.update( jMsg );
		return mac.doFinal();
	}

	function debugLog( required input ) {
		if ( structKeyExists( request, "log" ) && isCustomFunction( request.log ) ) {
			if ( isSimpleValue( arguments.input ) ) {
				request.log( "AWS-SES: " & arguments.input );
			} else {
				request.log( "AWS-SES: (complex type)" );
				request.log( arguments.input );
			}
		} else if( this.debug ) {
			cftrace( text=( isSimpleValue( arguments.input ) ? arguments.input : "" ), var=arguments.input, category="AWS SES", type="information" );
		}
		return;
	}

	struct function apiRequest( string verb= "GET", struct args= {}, boolean parse= false ) {
		var http= {};
		var item= "";
		var out= {
			url= this.apiUrl&arguments.uri
		,	success= false
		,	error= ""
		,	status= ""
		,	statusCode= 0
		,	response= ""
		};
		arguments.headers[ "Date" ]= getHttpTimeString( now() );
		arguments.headers[ "X-Amzn-Authorization" ]= "AWS3-HTTPS AWSAccessKeyId=#this.accessKeyId#, Algorithm=HmacSHA256, Signature=" & toBase64( HMAC_SHA256( this.secretAccessKey, arguments.headers[ "Date" ] ) );
		// replaceList( urlEncodedFormat( arguments.args[ "Signature" ] ), "%2D", "-" ) 
		this.debugLog( "#arguments.args.action# Request:" );
		cfhttp( result="http", method=arguments.verb, url=this.endPoint, charset="utf-8", throwOnError=false, timeOut=this.httpTimeOut ) {
			for ( item in arguments.headers ) {
				cfhttpparam( encoded=false, name=item, type="header", value=arguments.headers[ item ] );
			}
			for ( item in arguments.args ) {
				if ( arguments.verb == "GET" ) {
					cfhttpparam( encoded=true, name=item, type="url", value=arguments.args[ item ] );
				} else {
					cfhttpparam( encoded=true, name=item, type="formfield", value=arguments.args[ item ] );
				}
			}
		}
		this.debugLog( "#arguments.args.action# Response:" );
		//this.debugLog( http );
		out.response= toString( http.fileContent );
		out.statusCode = http.responseHeader.Status_Code ?: 500;
		this.debugLog( out.statusCode );
		if ( len( out.error ) ) {
			out.success= false;
		} else if ( out.statusCode == "401" ) {
			out.error= "Error 401, unauthorized";
		} else if ( out.statusCode == "503" ) {
			out.error= "Error 503, submitting requests too quickly";
		} else if ( left( out.statusCode, 1 ) == "4" ) {
			out.error= "Error #out.statusCode#, transient error, resubmit.";
		} else if ( left( out.statusCode, 1 ) == "5" ) {
			out.error= "Error #out.statusCode#, internal aws error";
		} else if ( out.statusCode == "" ) {
			out.error= "unknown error, no status code";
		} else if ( out.response == "Connection Timeout" || out.response == "Connection Failure" ) {
			out.error= out.response;
		} else if ( out.statusCode != "200" ) {
			out.error= "Non-200 http response code";
		} else if ( find( "<IsValid>False</IsValid>", out.response ) ) {
			out.error= "Invalid Request";
		} else {
			out.success= true;
		}
		// parse response 
		if ( arguments.parse ) {
			try {
				out.xml= xmlParse( out.response  );
				if ( find( "<Errors>", out.response ) ) {
					out.error= out.xml.ItemLookupResponse.Items.Request.Errors.Error.Message.XmlText;
				}
			} catch (any cfcatch) {
				out.error= "XML Error: " & (cfcatch.message?:"No catch message") & " " & (cfcatch.detail?:"No catch detail");
			}
		}
		if ( len( out.error ) ) {
			out.success= false;
		}
		return out;
	}

	struct function verifyEmailAddress( required string EmailAddress, boolean parse= false ) {
		var args= {
			"Action"= "VerifyEmailAddress"
		,	"EmailAddress"= arguments.EmailAddress
		};
		return this.apiRequest( verb= "GET", args= args, parse= arguments.parse );
	}

	struct function deleteVerifiedEmailAddress( required string EmailAddress, boolean parse= false ) {
		var args= {
			"Action"= "DeleteVerifiedEmailAddress"
		,	"EmailAddress"= arguments.EmailAddress
		};
		return this.apiRequest( verb= "GET", args= args, parse= arguments.parse );
	}

	struct function listVerifiedEmailAddresses( boolean parse= true ) {
		var args= {
			"Action"= "ListVerifiedEmailAddresses"
		};
		var req= this.apiRequest( verb= "GET", args= args, parse= arguments.parse );
		var item= "";
		if ( arguments.parse && req.success ) {
			try {
				req.emailAddresses= "";
				if ( isDefined( "req.xml.XmlRoot.ListVerifiedEmailAddressesResult.VerifiedEmailAddresses" ) ) {
					for ( item in req.xml.XmlRoot.ListVerifiedEmailAddressesResult.VerifiedEmailAddresses.XmlChildren ) {
						req.emailAddresses &= ( len( req.emailAddresses ) ? "," : "" ) & item.XmlText;
					}
				}
			} catch (any cfcatch) {
				req.success= false;
				req.error= "XML Error: " & (cfcatch.message?:"No catch message") & " " & (cfcatch.detail?:"No catch detail");
			}
		}
		return req;
	}

	struct function getSendQuota( boolean parse= true ) {
		var args= {
			"Action"= "GetSendQuota"
		};
		var req= this.apiRequest( verb= "GET", args= args, parse= arguments.parse );
		if ( arguments.parse && req.success ) {
			try {
				req.SentLast24Hours= req.xml.XmlRoot.GetSendQuotaResult.SentLast24Hours.XmlText;
				req.Max24HourSend= req.xml.XmlRoot.GetSendQuotaResult.Max24HourSend.XmlText;
				req.MaxSendRate= req.xml.XmlRoot.GetSendQuotaResult.MaxSendRate.XmlText;
			} catch (any cfcatch) {
				req.success= false;
				req.error= "XML Error: " & (cfcatch.message?:"No catch message") & " " & (cfcatch.detail?:"No catch detail");
			}
		}
		return req;
	}

	struct function getSendStatistics( boolean parse= true ) {
		var args= {
			"Action"= "GetSendStatistics"
		};
		var req= this.apiRequest( verb= "GET", args= args, parse= arguments.parse );
		var item= "";
		if ( arguments.parse && req.success ) {
			req.data= [];
			try {
				if ( isDefined( "req.xml.XmlRoot.GetSendStatisticsResult.SendDataPoints" ) ) {
					for ( item in req.xml.XmlRoot.GetSendStatisticsResult.SendDataPoints.XmlChildren ) {
						arrayAppend( req.data, {
							timestamp= parseDateTime( replaceList( item.Timestamp.xmlText, "T,Z", " ," ) )
						,	deliveryAttempts= item.DeliveryAttempts.xmlText
						,	rejects= item.Rejects.xmlText
						,	bounces= item.Bounces.xmlText
						,	complaints= item.Complaints.xmlText
						} );
					}
				}
			} catch (any cfcatch) {
				req.success= false;
				req.error= "XML Error: " & (cfcatch.message?:"No catch message") & " " & (cfcatch.detail?:"No catch detail");
			}
		}
		return req;
	}

	struct function sendEmail(
		required string to
	,	string cc= ""
	,	string bcc= ""
	,	required string from
	,	string replyTo= arguments.from
	,	string failTo= this.defaultFailTo
	,	required string subject
	,	string textBody= ""
	,	string htmlBody= ""
	,	string charSet= this.defaultCharset
	,	boolean parse= true
	) {
		var args= {
			"Action"= "SendEmail"
		,	"Destination.ToAddresses.member.1"= listFirst( trim( arguments.to ), "," )
		,	"Source"= trim( arguments.from )
		,	"Message.Subject.Data"= trim( arguments.subject )
		,	"Message.Subject.Charset"= arguments.charSet
		};
		var out= "";
		var x= 0;
		if ( len( arguments.replyTo ) ) {
			for ( x=1 ; x<=listLen( arguments.replyTo ) ; x++ ) {
				args[ "ReplyToAddresses.member.#x#" ]= trim( listGetAt( arguments.replyTo, x ) );
			}
		}
		if ( len( arguments.failTo ) ) {
			args[ "ReturnPath" ]= trim( arguments.failTo );
		}
		if ( listLen( arguments.to ) > 1 ) {
			for ( x=2 ; x<=listLen( arguments.to ) ; x++ ) {
				args[ "Destination.ToAddresses.member.#x#" ]= trim( listGetAt( arguments.to, x ) );
			}
		}
		if ( len( arguments.cc ) ) {
			for ( x=1 ; x<=listLen( arguments.cc ) ; x++ ) {
				args[ "Destination.CcAddresses.member.#x#" ]= trim( listGetAt( arguments.cc, x ) );
			}
		}
		if ( len( arguments.bcc ) ) {
			for ( x=1 ; x<=listLen( arguments.bcc ) ; x++ ) {
				args[ "Destination.BccAddresses.member.#x#" ]= trim( listGetAt( arguments.bcc, x ) );
			}
		}
		if ( len( arguments.textBody ) ) {
			args[ "Message.Body.Text.Data" ]= arguments.textBody;
			args[ "Message.Body.Text.Charset" ]= arguments.charSet;
		}
		if ( len( arguments.htmlBody ) ) {
			args[ "Message.Body.Html.Data" ]= arguments.htmlBody;
			args[ "Message.Body.Html.Charset" ]= arguments.charSet;
		}
		if ( this.throttleDelay > 0 && this.lastSend > 0 ) {
			var wait= this.throttleDelay - ( getTickCount() - this.lastSend );
			if ( wait > 0 ) {
				this.debugLog( "!!AUTOMATIC AWS-SES THROTTLE OF #wait#/ms" );
				sleep( wait );
			}
		}
		out= this.apiRequest( verb= "POST", args= args, parse= true );
		if ( this.throttleDelay > 0 ) {
			this.lastSend= getTickCount();
		}
		if ( arguments.parse && out.success ) {
			try {
				out.messageID= out.xml.XmlRoot.SendEmailResult.MessageId.XmlText;
			} catch (any cfcatch) {
				out.success= false;
				out.error= "Failed to parse xml response: " & cfcatch.message;
			}
		}
		return out;
	}

}
