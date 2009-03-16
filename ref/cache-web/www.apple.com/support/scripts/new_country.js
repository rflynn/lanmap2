function jumpTo(targ,selObj){
	   var loc=selObj.options[selObj.selectedIndex].value;
	   if (loc){
	       eval("location='"+loc+"'");
	   }
	   else{
	       selObj.selectedIndex=0;
	   }
}
