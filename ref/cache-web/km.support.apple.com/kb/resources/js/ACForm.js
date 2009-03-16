var ACForm = {

	validateEmail : function(value) {
		if (/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(value)){
			return true;
		}
		return "Invalid e-mail address! Example: webmaster@apple.com.";
	},
	
	validateCharacters : function(value, list, inverse) {
		// if inverse parameter is set to true it will validate if the value passed has any characters
		// that are NOT in the list. otherwise it will validate if all characters are in the list

		var strChar;
		var blnResult = true;
		
		for (var i = 0; i < value.length && blnResult == true; i++) {
			strChar = value.charAt(i);
			if (inverse) {
				if(list.indexOf(strChar) != -1) {
					blnResult = false;
				}
			}
			else {
				if(list.indexOf(strChar) == -1) {
					blnResult = false;
				}
			}
			
		}
		
		return blnResult;
		
	},
	
	validateAllNumeric : function(value) {
		return ACForm.validateCharacters(value, "0123456789.-");
	},
	
	validateNonNumeric : function(value) {
		return ACForm.validateCharacters(value, "0123456789.-", true);
	},
	
	validateAlphaNumeric : function(value) {
		return ACForm.validateCharacters(value, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
	},
	
	validateSize : function(value, size) {
		
		if(value.length!=size) {
			return "Length is different from the required " + size + " characters.";
		}
		return true;

	},
	
	validateMaxSize : function(value, size) {
		
		if(value.length>size) {
			return "Length is greater then " + size + " characters.";
		}
		return true;

	},
	
	validateDate : function(value) {
		
		var RegExPattern = /^(?=\d)(?:(?:(?:(?:(?:0?[13578]|1[02])(\/|-|\.)31)\1|(?:(?:0?[1,3-9]|1[0-2])(\/|-|\.)(?:29|30)\2))(?:(?:1[6-9]|[2-9]\d)?\d{2})|(?:0?2(\/|-|\.)29\3(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))|(?:(?:0?[1-9])|(?:1[0-2]))(\/|-|\.)(?:0?[1-9]|1\d|2[0-8])\4(?:(?:1[6-9]|[2-9]\d)?\d{2}))($|\ (?=\d)))?(((0?[1-9]|1[012])(:[0-5]\d){0,2}(\ [AP]M))|([01]\d|2[0-3])(:[0-5]\d){1,2})?$/;
	    if ((value.match(RegExPattern)) && (value.value!='')) {
	        return true;
	  	} else {
	        return 'Enter date as month, day, and four digit year. You may use a slash, hyphen or period to separate the values. Example: mm/dd/yyyy.'; 
	    } 

	},
	
	validateTest : function(validator, input, params) {
	
		var result = eval("ACForm." + validator + "('" + input + "'" + (params!=undefined ? ", " + params: "")  + ");" );
		if(result!=true) {
			//alert(result);
			console.warn(validator + "() did NOT validate " + input);
		}
		else {
			console.info(validator + "() validated " + input);
		}
	},
	
	validateSerialNumber : function(value) {
		if(ACUtil.validateSerialNumber(value)) {
			return true;
		}
		else {
			return "Not a valid serial number.";
		}
	},
	
	validate : function() {
		var formFields = $('dynamicform-outer-div').getElementsByClassName('formfield');
		var formLabels = $('dynamicform-outer-div').getElementsByClassName('formlabel');
		
		for(var i=0;i<formFields.length;i++) {
		
			var inputField = formFields[i].childNodes[1];
			var fieldLabel = ACUtil.trim(formLabels[i].innerHTML.replace("<span class=\"required\">*</span>",""));
			var errorMsg = null;
			
			if(formFields[i].getElementsByTagName('input')[0]!=undefined || formFields[i].getElementsByTagName('textarea')[0]!=undefined) {
			
				if(formFields[i].id.indexOf("_")!=-1) {
					
					// means we have a validation to do here
					
					var validationType = formFields[i].id.substring(formFields[i].id.indexOf("_")+1);
					var validationNumber = validationType.replace(/[EN]/g, "");
					
					if(validationType.indexOf("D")!=-1) {
						errorMsg = ACForm.validateDate(inputField.value);
					}
					else if(validationType.indexOf("SN")!=-1) {
						errorMsg = ACForm.validateSerialNumber(inputField.value);
					}
					else if(validationType.indexOf("AN")!=-1) {
						errorMsg = ACForm.validateAlphaNumeric(inputField.value);
					}
					else if(validationType.indexOf("A")!=-1) {
						errorMsg = ACForm.validateNonNumeric(inputField.value);
					}
					else if(validationType.indexOf("E")!=-1) {
						errorMsg = ACForm.validateEmail(inputField.value);
					}
					else if(validationType.indexOf("N")!=-1) {
						errorMsg = ACForm.validateSize(inputField.value, validationNumber);
					}
					else if(validationType.indexOf("L")!=-1) {
						errorMsg = ACForm.validateMaxSize(inputField.value, validationNumber);
					}
					
				}
			
			} 
			
			// now check for any required fields

			if(formFields[i].getElementsByTagName('input')[0]!=undefined && inputField.name.indexOf("REQ~")==0) {
				
				if(inputField.type=="radio" || inputField.type=="checkbox") {
					
					var inputFields = formFields[i].getElementsByTagName('input');
					var isChecked = false;
					
					for(var it=0;it<inputFields.length;it++) {
						if(inputFields[it].checked) {
							isChecked = true;
						}
					}
					
					if(!isChecked) {
						errorMsg = "Required field";
					}
					
				}
				else if(inputField.value=='') {
					errorMsg = "Required field";
				}
				
			}
			else if(formFields[i].getElementsByTagName('select')[0]!=undefined) {
				//dropdown will always have something preselected so required check is not needed
			}
			
			if(errorMsg!=null && errorMsg!=true) {
				alert("Problem with value for '" + fieldLabel + "':\n" + errorMsg);
				return false;
			}
			
		}
		
		return true;
		
	},
	
	submitForm : function() {
	
		document.dynamicform.setAttribute('id', 'dynamicform');
		
		if(ACForm.validate()) {
			$('dynamicform-submit').style.display = "none";
			
			Effect.Fade( $('dynamicform-outer-div') , {
			duration: .2,
			afterFinish: function(){ 
				$('dynamicform-send').style.display = "block";
		
					// need to send the form as multipart because of Inquira restrictions
					ACUtil.ajaxFormMultipart('dynamicform', ACForm);
					
				}
			} );
		}
		
		return false;
	},
	
	done : function(responseText) {
	
		if(responseText=="Success") {
			$('dynamicform-send').style.display = "none";
			$('dynamicform-done').style.display = "block";
		}
		else {
			ACForm.error("There was a problem submitting the form. Please try again!");
		}
		
	},
	
	error : function(errorMessage) {
		alert(errorMessage);
		
		$('dynamicform-send').style.display = "none";
		$('dynamicform-done').style.display = "none";
		$('dynamicform-submit').style.display = "block";
		
		Effect.Appear( $('dynamicform-outer-div') , {duration: .2} );
	}
	
}


/*
Event.observe(window, 'load', function() {
	ACForm.validateTest("validateSerialNumber", "71729AJSWH8");
	ACForm.validateTest("validateEmail", "example@vikingstad.com");
	ACForm.validateTest("validateAllNumeric", "123132");
	ACForm.validateTest("validateNonNumeric", "adasdsas");
	ACForm.validateTest("validateAlphaNumeric", "example");
	ACForm.validateTest("validateSize", "abcde", 5);
	ACForm.validateTest("validateDate", "04-20-1980");
	ACForm.validateTest("validateMaxSize", "dasdsadas", 20);
});
*/

