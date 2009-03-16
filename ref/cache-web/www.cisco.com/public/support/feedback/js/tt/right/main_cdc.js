// main_cdc.js
// Author: Jim Leonard
// Date: 11/04/2003


var sh = '<script src=\"';
var st = '\"></scrip'+ 't>';
var sv = location.host;
var fl;	

if ( sv.match('tools') ) { 
	if ( sv.match('stage') ) {
		sv = 'cco-stage'
	}else{
		sv = 'cisco.com'
	}
}

var jp = location.protocol + '//' + sv + '/public/support/feedback/js/tt/right/';

if ( document.URL.match('/en/US/') ) { 
	fl = 'cdcdoc.js'
}else{
	fl = 'cdctool.js'
}

document.writeln( sh + jp + fl + st );

