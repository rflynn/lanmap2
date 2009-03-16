var ACUtil = {

	httpRequest: null,
   
    'ajaxFormMultipart' : function(formElement, callback) {
   
		/*
		This function is only needed for Inquira specific form submissions that have to be
		of content type multipart. It will submit all the form elements in the formElement
		passed in.
		
		Hopefully this can be accomplished by extending the Ajax.Request object of Prototype
		at a later time.
		*/
   		
   		var currentUri = ACUtil.getCurrentUri();
   		
		if (typeof XMLHttpRequest != 'undefined') {
			httpRequest = new XMLHttpRequest();
		}
		else if (typeof ActiveXObject != 'undefined') {
			// need try/catch here in reality
			httpRequest = new ActiveXObject('Microsoft.XMLHTTP');
		}
		if (httpRequest != null) {
			var boundaryString = 'AaB03x';
			var boundary = '---------------------------11717337490392519956128404';
			var requestBody = '';

			var elems = $(formElement).elements;
			
			for (var ix=0; ix < elems.length; ix++) {
				var elem = elems[ix];
				if(elem.type!="radio" || (elem.type=="radio" && elem.checked==true)) {
					requestBody += "--" + boundary + "\nContent-Disposition: form-data; name=\"" + elem.name + "\"\r\n";
					requestBody += "\r\n";
					requestBody += elem.value + "\r\n";
				}
	
			}
			requestBody += "--" + boundary + "--\r\n";
			
			//alert(requestBody);
			
			httpRequest.open('POST', currentUri, true);
			if (typeof httpRequest.setRequestHeader != 'undefined') {
				httpRequest.setRequestHeader('Content-Type','multipart/form-data; boundary=' + boundary);
				//httpRequest.setRequestHeader('Content-Length', requestBody.length);
				httpRequest.onreadystatechange = function (evt) {
					if (httpRequest.readyState == 4) {
						//console.log("resp:  " + httpRequest.responseText);
						if(httpRequest.status==200) {
							callback.done(ACUtil.trim(httpRequest.responseText));
						}
						else {
							callback.error('Error: ' + httpRequest.status + ' ' + httpRequest.statusText);
						}
						
					}
				};
				//console.log(requestBody);
				httpRequest.send(requestBody);
			}
			
		}
		
	},
	
	// this function will send a request back to the origin server to register an article view
	// if served through akamai
	
	'reportView': function(documentId, locale) {
		new Ajax.Request('/kb/index?page=reportview&id=' + documentId + "&viewlocale=" + locale, { method:'get',
		  onSuccess: function(transport, json){
		      // do nothing on return
		    }
		  });
	},

	'writeCookie' : function(name, value, sessionBased) {
		var date = new Date();
		var expires = '';
		
		if(sessionBased==undefined) {
			date.setTime(date.getTime()+(24*60*60*1000*30));
			expires = "; expires="+date.toGMTString();
		}
		document.cookie = name+"="+escape(value)+expires+"; path=/; domain=.apple.com";
   },
   
	'toggleSearchTips' : function() {
		
		if( $('pb-searchtips').visible() ) {
			$('searchtipslink').removeClassName('searchtips-down');
			Effect.BlindUp('pb-searchtips', { duration: 0.3 });
		} else {
			$('searchtipslink').addClassName('searchtips-down');
			Effect.BlindDown('pb-searchtips', { duration: 0.3 });
		}	
	},
	
   'readCookie' : function(name) {
		var nameEQ = name + "=";
		var ca = document.cookie.split(';');
		for(var i=0;i < ca.length;i++) {
			var c = ca[i];
			while (c.charAt(0)==' ') c = c.substring(1,c.length);
			if (c.indexOf(nameEQ) == 0) return unescape(c.substring(nameEQ.length,c.length));
		}
		return null;
	},
	
	'inputCleanup' : function(cleanMe) {
		cleanMe = cleanMe.replace(/\&/g, "&amp;");
		//cleanMe = cleanMe.replace(/\"/g, "&quot;");
		
		cleanMe = cleanMe.replace(/\</g, "&lt;");
		cleanMe = cleanMe.replace(/\>/g, "&gt;");
		cleanMe = cleanMe.replace(/\+/g, " ");
		return cleanMe;
	},
	
	'clone': function(object) {
		// will clone a javascript object (as long as it conforms to JSON)
		var json = Object.toJSON(object);
		return eval(json.evalJSON(true));
	},
	
	'reverseInputCleanup' : function(cleanMe) {
		cleanMe = cleanMe.replace(/\&amp;/g, "&");
		//cleanMe = cleanMe.replace("&quot;", "\"");
		
		cleanMe = cleanMe.replace(/\&lt\;/g, "<");
		cleanMe = cleanMe.replace(/\&gt\;/g, ">");
		cleanMe = cleanMe.replace(/ /g, "+");
		return cleanMe;
	},
	
	'validateSerialNumber' : function(value) {
	
		if( value.length != 11 && value.length != 12 && value.length != 18) {
	        return false;
	    }
		
		if (value.length != 18) {
		
			yrWkStr = value.substr(2, 3)
			if(isNaN(yrWkStr) == true) {
				return false;
			}
			else {
				wkStr = yrWkStr.substr(1, 2)
				wk = parseInt(wkStr, 10)
				if(wk < 1 || wk > 53) {
					return false;
				}
				else {
					return true;
				}
			}
		}
		else {
			if(isNaN(value) == true){
				return false;
			}
			else {
			
				return true;
			}
		}
	},
	
	'trim' : function(stringToTrim) {
		if(stringToTrim!=undefined) {
			return stringToTrim.replace(/^\s+|\s+$/g,"");
		}
		else {
			return stringToTrim;
		}
	},
	
	'removeBreaks' : function(stringToRemove) {
		if(stringToRemove!=undefined) {
			return stringToRemove.replace(/[\r\n\t]+/g, "");
		}
		else {
			return stringToRemove;
		}
	},
	
	'getCurrentUri' : function() {
		var uri = ACUtil.parseUri();
		var port = (uri.port!="80" && uri.port!="") ? ":" + uri.port: "";
		var currentUri = 'http://' + uri.domain + port + uri.directoryPath.substring(0, uri.directoryPath.length-1);
		return currentUri;
	},
	
	'parseUri' : function(sourceUri) {
		sourceUri = sourceUri==undefined ? window.location.href : sourceUri;
		var uriPartNames = ["source","protocol","authority","domain","port","path","directoryPath","fileName","query","anchor"];
		var uriParts = new RegExp("^(?:([^:/?#.]+):)?(?://)?(([^:/?#]*)(?::(\\d*))?)?((/(?:[^?#](?![^?#/]*\\.[^?#/.]+(?:[\\?#]|$)))*/?)?([^?#/]*))?(?:\\?([^#]*))?(?:#(.*))?").exec(sourceUri);
		var uri = {};
		
		for(var i = 0; i < 10; i++) {
			uri[uriPartNames[i]] = (uriParts[i] ? uriParts[i] : "");
		}
		
		if(uri.directoryPath.length > 0) {
			uri.directoryPath = uri.directoryPath.replace(/\/?$/, "/");
		}
		return uri;
	},
	
	
	'open' : function(element) {
		$(element).style.display = "block";
    },
	
    'close' : function(element) {
		$(element).style.display = "none";
    },

	'callInProgress' : function(xmlhttp) {
		switch (xmlhttp.readyState) {
			case 1: case 2: case 3:
				return true;
			break;
			// Case 4 and 0
			default:
				return false;
			break;
		}
	},
	
	'submitSearch' : function() {
		var searchTerm = $('searchsupport').value;
		
		if(ACUtil.trim(searchTerm)=="") {
			return false;
		}
		else {
			return true;
		}
	},
	
	'randomString' : function () {
		var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
		var string_length = 8;
		var randomstring = '';
		for (var i=0; i<string_length; i++) {
			var rnum = Math.floor(Math.random() * chars.length);
			randomstring += chars.substring(rnum,rnum+1);
		}
		return randomstring;
	},
	
	'gup' : function (name) {
		name = name.replace(/[\[]/,"\\\[").replace(/[\]]/,"\\\]");
		var regexS = "[\\?&]"+name+"=([^&#]*)";
		var regex = new RegExp( regexS );
		var results = regex.exec( window.location.href );
		if( results == null ) return "";
		else return results[1];
	},
	
	'toggleCollapse': function (divBox, quickie) {
		var collapsedDiv = divBox.nextSibling;
  		
  		while(collapsedDiv.nodeName=="#text"){
			collapsedDiv=collapsedDiv.nextSibling;
		}
  		
  		Element.removeClassName(divBox, "collapse");
  		Element.removeClassName(divBox, "collapse-down");
  		
		if(collapsedDiv.style.display=="" || collapsedDiv.style.display=="block") {
			if(quickie!==undefined) Effect.BlindDown(collapsedDiv, { delay:0.2 } );
			else collapsedDiv.style.display = "none";
			divBox.addClassName("collapse");
		}
		else {
			if(quickie!==undefined) Effect.BlindUp(collapsedDiv, { delay:0.2 } );
			else collapsedDiv.style.display = "block";
			divBox.addClassName("collapse collapse-down");
		}
	},
	
	'expandAll': function () {
		var collapsable = $('articlecontent').getElementsByClassName("collapse");

		for(var i=0; i<collapsable.length; i++) {
			var collapsedDiv = collapsable[i].nextSibling;
			
			while(collapsedDiv.nodeName=="#text"){
				collapsedDiv=collapsedDiv.nextSibling;
			}
	  		if(collapsedDiv!=null) {
	  			collapsable[i].addClassName("collapse-down");
	  			collapsedDiv.style.display = "block";
	  		}
	  	}
	},
	
	'collapseAll': function () {
		var collapsable = $('articlecontent').getElementsByClassName("collapse");
		for(var i=0; i<collapsable.length; i++) {
	  		var collapsedDiv = collapsable[i].nextSibling;
	  		
			while(collapsedDiv.nodeName=="#text"){
				collapsedDiv=collapsedDiv.nextSibling;
			}
	  		if(collapsedDiv!=null) {
	  			collapsable[i].removeClassName("collapse-down");
	  			collapsedDiv.style.display = "none";
	  		}
	  	}
	},
	
	'setPOD': function(str){
		var today = new Date();
		var expiry = new Date(today.getTime() + 28 * 24 * 60 * 60 * 1000); // plus 28 days
		var expireVal = expiry.toGMTString();
		document.cookie = 'POD' + "=" + str + "; path=/; domain=.apple.com; expires=" + expireVal;
	},
	
	'clickTracking': function(title,url) {
		var s = s_gi(s_account);
	    var podcountry = this.readCookie('POD')!==null ? this.readCookie('POD').substring(0,2).toUpperCase() : 'US';
		
		var url = url!==undefined ? url: document.URL;
    	var title = title!==undefined && title!="" ? document.title + " - " + title + " (" + podcountry + ")" : document.title + " (" + podcountry + ")";
		//console.log(title);
	    s.pageName = title;
	    s.prop1 = '';
	    s.prop2 = '';
	    s.prop4 = url;
	    s.prop5 = '';
	    s.prop6 = s.getQueryParam('cp')+": "+title;
	    s.events = '';
	    s.pageURL = url.toLowerCase();
	    s.referrer = s.fl(s.wd.location ? s.wd.location : '', 255);
	    void(s.t());
	},
	
	'getOffers': function(productIds, origin, locale) {
	
		var dynamicScript = new JSONscriptRequest(KmLoader.akamaiUrl + '/kb/index?page=offer&productid=' + productIds + '&origin=' + origin + '&locale=' + locale + '&callback=ACUtil.showOffers');
		
		if(dynamicScript.headLoc) {
		
			try{
				dynamicScript.buildScriptTag();
				dynamicScript.addScriptTag();
			}
			catch(ex) {
				// IE 5 for Mac will throw an exception here.
			}
		}
	},
	
	'showOffers': function(json) {
		if(!json || json.offers.length==0) {
			return;
		}
		
		for(var i=0;i<json.offers.length;i++) {
			var offerDivName = 'offer_' + json.offers[i].position.toLowerCase();
			
			if(json.offers[i].offer!='' && $(offerDivName)) {
				$(offerDivName).innerHTML = json.offers[i].offer;
				$(offerDivName).show();
			}
		}
	}
};

Ajax.Responders.register({
	onCreate: function(request) {
		request['timeoutId'] = window.setTimeout( function() {
			// If we have hit the timeout and the AJAX request is active, abort it and let the user know
			if (ACUtil.callInProgress(request.transport)) {
				request.transport.abort();
				// Run the onFailure method if we set one up when creating the AJAX object
				if (request.options['onFailure']) {
					request.options['onFailure'](request.transport, request.json);
				}
			}
		},
		60000 // 60 seconds 
		);
	},
	onComplete: function(request) {
		// Clear the timeout, the request completed ok
		window.clearTimeout(request['timeoutId']);
	}
});

Event.observe(window, 'load', function() {

  // check for collapseable headings if this is an article
  if($('articlecontent') && $('articlecontent').getElementsByClassName("collapse").length!=0) {
  	var collapsable = $('articlecontent').getElementsByClassName("collapse");
  	for(var i=0; i<collapsable.length; i++) {
  		collapsable[i].innerHTML = "<a href=\"javascript:void(0);\" onclick=\"ACUtil.toggleCollapse(this.parentNode);return false;\" style=\"margin-left:-20px;padding-left:20px;\">" + collapsable[i].innerHTML + "</a>";
		ACUtil.toggleCollapse(collapsable[i]);
  	}
  	
  	if($('collapser')) {
  		$('collapser').style.display = 'block';
    }
  }
  
  Event.observe(document, 'keypress', function(e){ 
	var code;
	if (!e) var e = window.event;
	if (e.keyCode) code = e.keyCode;
	else if (e.which) code = e.which;
	
	// disable any shortcuts when in a textarea/field:
	
	var element;
	if(e.target) element=e.target;
	else if(e.srcElement) element=e.srcElement;
	if(element.nodeType==3) element=element.parentNode;
	var character = String.fromCharCode(code);
	
	if((character=="" || character=="")) {
		// if user presses escape (empty character means escape in Safari)
		if((element.name=="recipient" || element.name=="email_sendto") && $('email-open')) {
			ACEmail.open();
			element.blur();
		}
		
	}
	else if((element.tagName == 'INPUT' || element.tagName == 'TEXTAREA')) {
		return;
	}
	else {
		
		if($('email-open') && !$('email-open').visible() && (character=="e" || character=="E")) {
			scroll(0,0);
			ACEmail.open();
		}
		else if($('email-open') && $('email-open').visible() && (character=="e" || character=="E")) {
			scroll(0,0);
			window.setTimeout("$('email-address').focus();", 5);
		}
		
	}
	
  });
});
