//初始化事件
function initEvent(){
	$("#replacement").click(function(){
        $(".newUser").show();
        $(".oldUser").hide();
    })
}
var isOld = 0;
function initData(){
	//设置页面内容
	setPageInfo();
}

//设置页面内容
function setPageInfo(){
	//轮播
	setCarouseImg($("#adv2"),"pc");
}
//初始化认证数据
function initAuth(ifisOld){
	
	if(ifisOld){//老用户
		$("#oldUser").show();
		$("#newUser").hide();
		isOld = true;
	}else{
		provision();
		$("#oldUser").hide();
		$("#newUser").show();
	}
	isOld = ifisOld;
}

//处理老用户手机号，显示
function dealMobile(mobile){
	var regexp = /^(13[0-9]|15[012356789]|17[0-9]|18[0-9]|14[57])[0-9]{8}$/;
	if(!regexp.test(mobile)){
		return false;
	}else{
		$("#phone").val(mobile);
		return true;
	}
}

//获取服务码
var InterValObj; //timer变量，控制时间
var count = 60; //间隔函数，1秒执行

var curCount;//当前剩余秒数
function getAuthCode() {
	$("#getAuth").attr("disabled", "disabled");
	curCount = count;
	var phone = $("#phone").val();
	var telReg = !!phone.match(/^(0|86|17951)?(13[0-9]|15[012356789]|17[0-9]|18[0-9]|14[57])[0-9]{8}$/);
	if(!phone){
		$(".tip").html("请填写手机号！");
		// alert("请填写手机号！");
		$("#getAuth").removeAttr("disabled");
		return false;
	}else{
		$(".tip").html("");
	}
	if(telReg == false) {
		$(".tip").html("请填写正确的手机号！");
		// alert("请填写正确的手机号！");
		$("#getAuth").removeAttr("disabled");
		return false;
	}else{
		$(".tip").html("");
	}
	$.ajax({
		type : 'GET',
        url : "/cgi-bin/portal_cgi?opt=text_code&name="+phone,
        data: null,
        success : function(data) {
            if(data.code == 0) {
			   $(".tip").html("服务码已发送至您的手机，一分钟内没收到短信，请重新获取服务码");
               $("#authId").val(data._key);
               $("#getAuth").html("重获服务码" + curCount);
        	   InterValObj = window.setInterval(setRemainTime, 1000);
            } else if(data.code == "2") {
				$(".tip").html("重复获取，请一分钟后再试");				
				$("#getAuth").removeAttr("disabled");//启用按钮
            }else if(data.code == 101) {
				$(".tip").html("网络异常,请重新连接");
				$("#getAuth").removeAttr("disabled");//启用按钮
			}else {
				$(".tip").html("短信发送失败，请重新获取服务码");
				$("#getAuth").removeAttr("disabled");//启用按钮
            }
        },
        error: function() {
        	$("#getAuth").removeAttr("disabled");//启用按钮
			$(".tip").html("短信发送失败，请重新获取服务码");
        }
	});
}

//timer处理函数
function setRemainTime() {
    if (curCount == 0) {
        window.clearInterval(InterValObj);//停止计时器
        $("#getAuth").removeAttr("disabled");//启用按钮
        $("#getAuth").html("重获服务码");
    }
    else {
        curCount--;
        $("#getAuth").html("重获服务码" + curCount);
    }
}

//遵守条款复选框
function provision(){
	$("#auth-agree-checkbox").prop("checked",true);
	var checkboxLength=$("[name = 'auth-agree-checkbox']:checkbox:checked").length;
	$('#auth-agree-checkbox').bind('click',function() {
		if (checkboxLength == 0) {
			alert('请您阅读并确认是否同意遵守《无线上网使用条款》。');
			$('#lock').attr('disabled', 'disabled').css({"background-color": "gray", "border-color": "gray"});
			checkboxLength = 1
		} else {
			$('#lock').removeAttr('disabled').css({"background-color": "#36a9e5", "border-color": "#36a9e5"});
			checkboxLength = 0
		}
	});
}

//上网认证
function auth(event) {
	var tag = $(event.target);
	var phone = $("#phone").val();
	var authCode = $("#authCode").val();
	var authId = $("#authId").val();

	//校验
	var telReg = !!phone.match(/^(0|86|17951)?(13[0-9]|15[012356789]|17[0-9]|18[0-9]|14[57])[0-9]{8}$/);
	if(!isOld||isOld=="false"){
		if(!phone){
			$(".tip").html("请输入手机号");
			tag.removeAttr("disabled");//启用按钮
			return false;
		}else{
			$(".tip").html("");
		}
		if(!telReg) {
			$(".tip").html("手机号错误");
			tag.removeAttr("disabled");//启用按钮
			return false;
		}else{
			$(".tip").html("");
		}
		if(authCode==""||null==authCode){
			$(".tip").html("请输入服务码");
			tag.removeAttr("disabled");//启用按钮
			return false;
		}else{
			$(".tip").html("");
		}
	}
	//开始认证
	tag.attr("disabled","disabled");//添加disabled属性
	tag.html('认证中...');
	var tempIsOld = 0;
	if(isOld == "true"){
		tempIsOld = 1;
	}
	var myurl;
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
		async: false,
		type : 'GET',
		url : myurl,
		data: null,
		success : function(data) {
			//认证成功
			if(data.code == 0) {
				$('.hideCtr').hide();
				$('#newSuccessMsg').show();
				$('#successMsg').show();
				$('#linkBtnHid').hide();
				$(".tip").html();
			} else if(data.code == 1){
				$(".tip").html("连接失败，请重试");
				tag.removeAttr("disabled");//启用按钮
				tag.html("连&nbsp;接");
			} else if(data.code == 2){
				$(".tip").html("网络状态已变化，请断开网络重新连接");
				tag.removeAttr("disabled");//启用按钮
				tag.html("连&nbsp;接");
			} else if(data.code == 3){
				$(".tip").html("您输入的服务码有误，请重新输入");
            	tag.removeAttr("disabled");//启用按钮
            	tag.html("连&nbsp;接");
            } else if(data.code == 4){
				$(".tip").html("服务码过期，请重新获取");
            	tag.removeAttr("disabled");//启用按钮
            	tag.html("连&nbsp;接");
			} else {
				$(".tip").html("连接失败，请重试");
				tag.removeAttr("disabled");//启用按钮
				tag.html("连&nbsp;接");
			}
		},
		error: function() {
			$(".tip").html("连接失败，请重试");
			tag.removeAttr("disabled");//启用按钮
			tag.html("连&nbsp;接");
		}
	});
}
