Event.observe(window, 'load', function() {
	
	KmLoader.success = function(json, requestId) {
		var componentName = KmLoader.getDiv(requestId);
		
		var contentDiv = $(componentName);
		var outerContentDiv = $('outer_' + componentName);
		
		contentDiv.innerHTML = '';
		
		if(json==undefined || json==null) {
			//alert('Something went wrong. Please try again!') 
		}
		else if(json['results'].length>0) {
			
			var maxLength = componentName=='related_discussions' ? 33 : 66;
			var maxItems = 5;
			for(i=0;i<json['results'].length && i<maxItems;i++) {
				//do not show results that have the same title as the article we are looking at
				var showResult = ((componentName=="related_articles" || componentName=="related_hotdiscussions") && 
					ACUtil.trim(json.results[i].title).substring(0, 60)==ACUtil.trim($('article').getElementsByTagName('h1')[0].innerHTML).substring(0,60)) ? false : true;
				
				if(showResult) {
					var title = json.results[i].title.length>maxLength ? json.results[i].title.substring(0, maxLength) + '...' : json.results[i].title;
					contentDiv.innerHTML += "<li><a href='" + json.results[i].url + "'>" + title + "</a></li>";
				}
				else {
					maxItems++;
				}
			}
			
			if(ACUtil.trim(contentDiv.innerHTML)!='') {
				Effect.BlindDown(outerContentDiv , {duration: 0.2} );
			}
		}
		
	}
	
	KmLoader.error = function(errorMsg, requestId) {
		var contentDiv = $(KmLoader.getDiv(requestId));
		var outerContentDiv = $('outer_' + KmLoader.getDiv(requestId));
		
		contentDiv.innerHTML = '';
		//alert('RequestId: ' + requestId + " Error: " + errorMsg);
	}
	
	KmLoader.getDiv = function(requestId) {
		var divName;
		if(requestId==1) {
			divName = 'related_discussions';
		}
		else if(requestId==2) {
			divName = 'related_articles';
		}
		else if(requestId==3) {
			divName = 'related_hotdiscussions';
		}
		return divName;
	}

});