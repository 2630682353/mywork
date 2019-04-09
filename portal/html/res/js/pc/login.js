$(function(){
    $(".validateInput").click(function(){
        $(this).addClass("activeInput");
        $(this).find("input").focus();
    });
    $(".validateInput input").blur(function(){
        if($.trim($(this).val()) == ""){
            $(this).parent().removeClass("activeInput");
        }
    });
    loadData();
});
var loadData = function(){
    var $userName = $("input.phoneNum");
    var $passWord = $("input.dynamicPwd");
    if($userName.val() != "" && $passWord.val() != ""){
        $userName.parent().addClass("activeInput");
        $passWord.parent().addClass("activeInput");
    };
};
function send(){
    $(".validate-content .code").attr("disabled","disabled");
    setTime(60);
}
function setTime(s){
    setTimeout(function(){
        s--;
        if(s>0){
            $("#time").text(s);
            setTime(s);
        }else{
            $("#time").text(60);
            $(".validate-content .code").removeAttr("disabled");
        }
    },1000);
}
function checkmobile(){
    var mobile = $(".validate-content input.phoneNum").val();
    var myreg = /^(0|86|17951)?(13[0-9]|15[012356789]|17[0678]|18[0-9]|14[57])[0-9]{8}$/;
    if(mobile == ""){
        $(".validate-prompt .cue").text("请填写手机号！");
    }else if(mobile.length!=11){
        $(".validate-prompt .cue").text("请填写正确的手机号！");
    }else if(!myreg.test(mobile)){
        $(".validate-prompt .cue").text("请填写正确的手机号！");
    }}

function reciprocal(){
    setTimes(6);
}
function setTimes(s){
    setTimeout(function(){
        s--;
        if(s>0){
            $("#time").text(s);
            setTimes(s);
        }else{
            $("#time").text(6);
        }
    },1000);
}
