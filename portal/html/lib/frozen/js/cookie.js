
var Cookie=(function(Cookie){
	/**
	 * 添加cookie
	 */
	Cookie.addCookie = function(name, value, days) {
		var str = name + "=" ;
		if( days > 0) { //为0时不设定过期时间，浏览器关闭时cookie自动消失
			var date = new Date(); 
            var ms = days * 3600 * 1000 * 24;
            date.setTime(date.getTime() + ms);  
            str = str + value +';expires=' + date.toGMTString();  //将值及过期时间一起保存至cookie中(需以GMT格式表示的时间字符串)
		}else{
			str = str + escape(value);
		}
		document.cookie = str+";path=/";
	};
	/**
	 * 获取cookie
	 */
	Cookie.getCookie = function(name){
		var nameEQ = name + "=";   
		var ca = document.cookie.split(';');    //把cookie分割成组  
		for(var i = 0; i < ca.length; i++) {  
			 var c = ca[i];                      //取得字符串 
			 while(c.charAt(0) ==' ') {          //判断一下字符串有没有前导空格  
			 	c = c.substring(1, c.length);      //有的话，从第二位开始取 
			 }  
			 if (c.indexOf(nameEQ) == 0) {       //如果含有我们要的name 
				return unescape(c.substring(nameEQ.length, c.length));    //解码并截取我们要值  			 	
			 }
		}
		return null;  
	};
	/**
	 * 
	 */
	Cookie.delCookie = function (name) {
	    var exp = new Date(); 
	    exp.setTime(exp.getTime() - 1); 
	    var cval=Cookie.getCookie(name); 
	    if(cval!=null) 
	        document.cookie= name + "="+cval+";expires="+exp.toGMTString(); 
	};
	return Cookie;
}(Cookie || {}));