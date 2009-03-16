var ACRating = {
	'send' : function(ratingNum) {
		
		ratingNum = ratingNum + 4;
		if(document.ratingform.elements[ratingNum]!=undefined) {
			document.ratingform.elements[ratingNum].checked = true;
			
			document.ratingform.setAttribute('id', 'ratingform');
			
			// need to send the form as multipart because of Inquira restrictions
			ACUtil.ajaxFormMultipart('ratingform', ACRating);
			
			$('rating').style.display = "none";
			$('rating-send').style.display = "block";
		}
		else {
			ACRating.error("There was a problem submitting the rating. Language not supported? Please try again!");
		}
    },
	
    'done' : function(responseText) {
   		if(responseText=="Success") {
			$('rating-send').style.display = "none";
			$('rating-done').style.display = "block";
		}
		else {
			ACRating.error("There was a problem submitting the rating. Please try again!");
		}
	},
	
    'error' : function(errorMessage) {
   		alert(errorMessage);
   
		$('rating-send').style.display = "none";
		$('rating-done').style.display = "none";
		$('rating').style.display = "block";
		
	}
	
};