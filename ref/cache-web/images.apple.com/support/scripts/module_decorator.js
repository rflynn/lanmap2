
Event.observe(window,'load',function(){

var inputs=document.getElementsByTagName('div');

for(var i=0;i<inputs.length;i++){
if(Element.hasClassName(inputs[i],'module')){

   var original = inputs[i]; 
   /* Make it the inner div of the four */ 
   original.className = original.className.replace('module', 'br'); 
   /* Now create the outer-most div */ 
   var mo = document.createElement('div'); 
   mo.className = 'module'; 
   /* Swap out the original (we'll put it back later) */ 
   original.parentNode.replaceChild(mo, original); 
   /* Create the two other inner nodes */ 
   var tl = document.createElement('div');
	tl.className = 'tl';
   var tr = document.createElement('div');
	tr.className = 'tr';
   var bl = document.createElement('div');
 	bl.className = 'bl';
   /* Now glue the nodes back in to the document */ 
   mo.appendChild(tl); 
   tl.appendChild(tr);
   tr.appendChild(bl);
   bl.appendChild(original); 



}
}
});

