//正则配置
var config = {
	mobile:/^(13[0-9]|15[012356789]|17[0-9]|18[0-9]|14[57])[0-9]{8}$/
};
var mobileTag = $("#mobile").closest(".auth-input");
var codeTag = $("#code").closest(".auth-input");
var isOld = 0;//记录当次是否为老用户
var failureCount = 0;//认证失败计数

var pageData;//页面配置数据
var nextUrl = "http://www.aviup.com";//下一页url
var current;//当前流程编号
//初始化字体/布局大小等
function initFont(){
	var wh = $(window).outerHeight();
	var ww = $(window).outerWidth();
	if(wh>627){
		$("html").css("font-size","12px");
	}else{
		$("html").css("font-size","12px");
	}
	if(wh<551){
		$(".auth-container").css("height","551px");
	}else{
		$(".auth-container").css("height",wh);
	}
	if((ww>414||ww==414)){
		var tmph = 551*ww/360;
		wh = wh>tmph?wh:tmph;
		$(".auth-container").css("height",wh);
		var fs = 10*ww/360;
		$("html").css("font-size",fs);
	}
}
//绑定事件
function initEvent(){
	$(window).resize(function(){
		initFont();
	});
	$("input").focus(function(){
		clearError();
	});
	$(".auth-agree a").click(function(){
		window.location.href="/static/portal/agreement.html";
	});
}
function clearError(){
	$(".auth-span-error").text("").css("display","none");
	$(".auth-input-error").removeClass("auth-input-error");
}
function initData(){
	//设置页面内容
	 setPageInfo();
}
var logoClickCount = 0;
var logoClickTimer;

//设置页面内容
function setPageInfo(){
	var $authLogoLeft = $(".auth-header");
	var $authAd = $(".auth-ad");
	//logo
	setSingleImg($authLogoLeft);

	//延时显示，避免轮播部分图片加载由小到大的过渡及内容部分的位移过渡
	setTimeout(function(){
		$('.carousel').css('opacity',1);
		$('.auth-content').show();
	},200);

	//960
	setCarouseImg($authAd,"mobile");
}

function initAuth(ifisOld){
	//0 不是，1 是

	if(ifisOld){
		$("#msgLogin").closest("div").hide();
		$("#auth_old").show();
		$("#auth_old_title").show();
		$("#auth").show().html("一键登录上网");
		$('.auth-agree').html('请点击“一键登录上网”按钮完成无线上网连接');
		isOld = 1;
	}else{
		$("#auth_new").show();
		$("#auth_new_title").show();
		$("#auth").show().html("确定");
		$('.auth-agree').html(
			'<label class=""><input name="checkbox" id="auth-agree-checkbox" type="checkbox" checked="checked" style="vertical-align: bottom;"/></label>'+
			'我已阅读并同意遵守<a href="/static/portal/huashu-agreement.html">《无线上网使用条款》</a>'
		);
		isOld = 0;
		provision()
	}

}

//更换手机
function changeMobile(){
	isOld = 0;
	$("#auth_old").hide();
	$("#auth_new").show();
	$("#mobile").val("");
}
//显示错误信息
function authError(msg,target){
	if(msg){
		target?target.addClass("auth-input-error"):$(".auth-input").addClass("auth-input-error");
		$(".auth-span-error").removeClass("auth-color-grey").text(msg).css("display","inline");
	}else{
		$(".auth-span-error").text("").css("display","none");
	}
}
function authTip(msg,target){
	if(msg){
		$(".auth-span-error").removeClass("auth-color-grey").text(msg).css("display","inline");
	}else{
		$(".auth-span-error").text("").css("display","none");
	}
}
//获取服务码
var InterValObj; //timer变量，控制时间
var count = 60; //间隔函数，1秒执行
var curCount;//当前剩余秒数
var getAuthTarget = $("#getAuth");
function getAuthCode() {
	clearError();
	getAuthTarget.attr("disabled", "disabled");
	curCount = count;
	var phone = $("#mobile").val();
	var telReg = config.mobile.test(phone);
	if(!phone){
		authError("请输入手机号",mobileTag);
		getAuthTarget.removeAttr("disabled");
		return false;
	}
	if(!telReg) {
		authError("手机号错误",mobileTag);
		getAuthTarget.removeAttr("disabled");
		return false;
	}

	$.ajax({
		type : 'GET',
        url : "/cgi-bin/portal_cgi?opt=text_code&name="+phone,
        
        data: null,
        success : function(data) {
            if(data.code == "0") {
				authTip("服务码已发送至您的手机，一分钟内没收到短信，请重新获取服务码",mobileTag);
				getAuthTarget.text("重获服务码" + curCount);
        	   InterValObj = window.setInterval(setRemainTime, 1000);
			} else if(data.code == "2") {
            	authError("重复获取，请一分钟后再试",mobileTag);
				getAuthTarget.removeAttr("disabled");//启用按钮
            } else if(data.code == 101) {
            	authError("网络异常,请重新连接",mobileTag);
				getAuthTarget.removeAttr("disabled");//启用按钮
            } else {
            	authError("短信发送失败，请重新获取服务码",mobileTag);
				getAuthTarget.removeAttr("disabled");//启用按钮
            }
        },
        error: function() {
			getAuthTarget.removeAttr("disabled");//启用按钮
        	authError("短信发送失败，请重新获取服务码",mobileTag);
        }
	});
}
//timer处理函数
function setRemainTime() {
    if (curCount == 0) {
        window.clearInterval(InterValObj);//停止计时器
		getAuthTarget.removeAttr("disabled");//启用按钮
		getAuthTarget.text("重获服务码");
    }
    else {
        curCount--;
        $("#getAuth").text("重获服务码" + curCount);
    }
}

//遵守条款复选框
function provision(){
	$("#auth-agree-checkbox").prop("checked",true);
	var checkboxLength=$("[name = 'auth-agree-checkbox']:checkbox:checked").length;
	$('#auth-agree-checkbox').bind('click',function() {
		if (checkboxLength == 0) {
			alert('请您阅读并确认是否同意遵守《无线上网使用条款》。');
			$('#auth').attr('disabled', 'disabled').css({"background-color": "gray", "border-color": "gray"});
			checkboxLength = 1
		} else {
			$('#auth').removeAttr('disabled').css({"background-color": "#36a9e5", "border-color": "#36a9e5"});
			checkboxLength = 0
		}
	});
}


//手机/微信 上网认证
function auth(event) {
	var $spanError = $(".auth-span-error");
	$spanError.removeClass("twinkling");
	if(failureCount==3){
		if(isOld==1){
			authError("网络异常，请断开网络重新连接！",$("#auth_old").find(".auth-old-input"));
		}else{
			authError("网络异常，请断开网络重新连接！");
		}
		setTimeout(function(){
			$spanError.addClass("twinkling");
		},500)
		return false;
	}
	clearError();
	var tag = $(event.target);
	tag.attr("disabled","disabled");//添加disabled属性
	var phone = $("#mobile").val();
	var authCode = $("#code").val();
	var authId = $("#authId").val();
	//校验
	var telReg = config.mobile.test(phone);
	if(isOld!=1){
		if(!phone){
			authError("请输入正确的手机号码",mobileTag);
			tag.removeAttr("disabled");//启用按钮
			return false;
		}
		if(!telReg) {
			authError("请输入正确的手机号码",mobileTag);
			tag.removeAttr("disabled");//启用按钮
			return false;
		}
		if(authCode==""||null==authCode){
			authError("请输入服务码",codeTag);
			tag.removeAttr("disabled");//启用按钮
			return false;
		}
	}
	//开始认证
	var myurl;
	tag.text("连接中...");
	var mac = $("#mac").val();
	var vlan = $("#vlan").val();
	var user_ip = $("#user_ip").val();
	if (isOld) {
		phone = $("#tel").val();
		authCode = $("#pwd").val();
		myurl = "/cgi-bin/portal_cgi?opt=auth&name="+phone+"&pwd="+authCode+"&mac="+mac+"&vlan="+vlan+"&user_ip="+user_ip;
	} else {
		myurl = "/cgi-bin/portal_cgi?opt=register&name="+phone+"&pwd="+authCode+"&mac="+mac+"&vlan="+vlan+"&user_ip="+user_ip;
	}
	
	$.ajax({
		type : 'GET',
		url : myurl,
        data: null,
        success : function(data) {
            if(data.code == 0) {
				setTimeout(function(){
					window.location.href=nextUrl;
				},500);
            } else if(data.code == 1){
            	if(isOld==1){
					authError("连接失败，请重试",$("#auth_old").find(".auth-old-input"));
					tag.text("一键登录上网");
				}else{
					authError("连接失败，请重试");
					tag.text("确定");
				}
            	tag.removeAttr("disabled");//启用按钮
            } else if(data.code == 2){
            	if(isOld==1){
					authError("网络状态已变化，请断开网络重新连接",$("#auth_old").find(".auth-old-input"));
					tag.text("一键登录上网");
				}else{
					authError("网络状态已变化，请断开网络重新连接");
					tag.text("确定");
				}
				$spanError.addClass("twinkling");
            	tag.removeAttr("disabled");//启用按钮
            } else if(data.code == 3){
            	authError("您输入的服务码有误，请重新输入");
            	tag.removeAttr("disabled");//启用按钮
            	tag.text("确定");
            } else if(data.code == 4){
            	authError("服务码过期，请重新获取",codeTag);
            	tag.removeAttr("disabled");//启用按钮
            	tag.text("确定");
            } else {
            	failureCount++;
            	if(isOld==1){
					authError("连接失败，请重试",$("#auth_old").find(".auth-old-input"));
					tag.text("一键登录上网");
				}else{
					authError("连接失败，请重试");
					tag.text("确定");
				}
            	tag.removeAttr("disabled");//启用按钮
            }
        },
        error: function() {
        	if(isOld==1){
				authError("网络异常，请断开网络重新连接！",$("#auth_old").find(".auth-old-input"));
			}else{
				authError("网络异常，请断开网络重新连接！");
			}
			$spanError.addClass("twinkling");
        	tag.removeAttr("disabled");//启用按钮
        	tag.text("确定");
        }
	});
}
