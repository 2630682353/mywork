

var current = "first";
var current_menu = "fl1";

function show_div(str_div, str_menu){
	document.getElementById(current).style.display="none";
	document.getElementById(str_div).style.display="block";
    document.getElementById(current_menu).style.backgroundColor="#9fdcf8";
    document.getElementById(current_menu).style.color="#333";
    document.getElementById(str_menu).style.backgroundColor="#fff";
    document.getElementById(str_menu).style.color="#0091db";
    current_menu = str_menu;
	current = str_div;
}

 var xhr = function(){
    if (window.XMLHttpRequest) {
        return new XMLHttpRequest();
    }else{
        return new ActiveObject('Micrsorf.XMLHttp');
    }
}();

function gettime() {
  var timestmp = (new Date()).valueOf();            
  return "&timestmp="+timestmp;
}


var set_info;
var zhezhao;
var waitimg;
var data_query = 1;
window.onload=function(){
    set_info=document.getElementById("set_info");
    zhezhao=document.getElementById("zhezhao");
    waitimg=document.getElementById("waitimg");
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now querying please wait...";
    xhr.open('get','/cgi-bin/hello.cgi?opt=main&function=get'+gettime());
    xhr.send(null);
}

xhr.onreadystatechange = function(){
    switch(xhr.readyState){
        case 4 : 
            //set_info.innerHTML="响应全部接受完毕";
            if ((xhr.status >= 200 && xhr.status < 300) || xhr.status == 304) {
                var data=JSON.parse(xhr.responseText);
                if (data.opt == 'check_login')
                    check_login(data);
                else if (data.opt == 'terminal')
                    result_handle(data,terminal,"Terminal");
                else if (data.opt == 'main')
                    result_handle(data,first_main,"");
                else if (data.opt == 'main2')
                    result_handle(data,first_main2,"");
                else if (data.opt == 'master')
                    result_handle(data,master,"Master");
                else if (data.opt == 'time')
                    result_handle(data,hand_time,"Time");
                else if (data.opt == 'data_source')
                    result_handle(data,data_source,"Measure node");
                else if (data.opt == 'manage')
                    result_handle(data,manage,"");
                else if (data.opt == 'meter_detail')
                    result_handle(data,meter_detail,"");
                else if (data.opt == 'version')
                    version(data);
                else if (data.opt == 'upload_file')
                    if (data.error != 0) {
                        end_show("Upload error");
                        document.getElementById("info_upload").style.display="none";
                    }
                    else {
                        end_show("Upload complete");
                        document.getElementById("info_upload").style.display="none";
                    }
            }
            break;
    }
}
function result_handle(data,func,module)
{
    if (data.function == 'set') {
        if (data.error != 0)
            end_show(module+"apply error");
        else 
            end_show(module+"apply success");
    } else {
        if (data.error != 0)
            end_show(module+"query error");
        else {
            end_show(module+"query success");
            func(data);
        }
    }
}
function master(data)
{
}
function terminal(data)
{
}
function manage(data)
{
    document.getElementById('cao_interval').value=data.cao_interval;
}
function hand_time(data)
{
    document.getElementById('ter_time').value=data.time;
}
function version(data)
{
    document.getElementById('device_id').innerHTML=data.device_id;
    document.getElementById('soft_version').innerHTML=data.soft_version;
    document.getElementById('hard_version').innerHTML=data.hard_version;
    document.getElementById('soft_pubdate').innerHTML=data.soft_pubdate;
    data_query = 0;
}
function reset()
{
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now applying please wait...";
    xhr.open('get','/cgi-bin/hello.cgi?opt=manage&function=set&flag=reset'+gettime());
    xhr.send(null);
}

function data_reset()
{
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now applying please wait...";
    xhr.open('get','/cgi-bin/hello.cgi?opt=manage&function=set&flag=data_reset'+gettime());
    xhr.send(null);
}

function part_init()
{
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now applying please wait...";
    xhr.open('get','/cgi-bin/hello.cgi?opt=manage&function=set&flag=part_init'+gettime());
    xhr.send(null);
}

function all_init()
{
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now applying please wait...";
    xhr.open('get','/cgi-bin/hello.cgi?opt=manage&function=set&flag=all_init'+gettime());
    xhr.send(null);
}

function end_show(infostr)
{
    zhezhao.style.display="block";
    set_info.innerHTML=infostr;
    waitimg.style.display="none";
    setTimeout("dis()",1200);
}
function dis(){
    zhezhao.style.display='none';
}

setInterval("myInterval()",2000000);//1000为1秒钟
function myInterval()
{
      xhr.open('get','/cgi-bin/hello.cgi?opt=check_login&function=get'+gettime());
        xhr.send(null);
}

function getdAllData(){

}
function check_login(data)
{
     if (data.login == 0) {
            alert('Login timeout or not login');
            window.location.href="index.html";
    }
}
function first_main(data)
{
    document.getElementById('master_ip').value=data.master_ip1;
    document.getElementById('master_port').value=data.master_port1;
    document.getElementById('master_apn').value=data.master_apn;
    document.getElementById('user').value=data.user;
    document.getElementById('pwd').value=data.pwd;
    document.getElementById('heartbeat').value=data.heartbeat;
    document.getElementById('ter_ip1').value=data.ter_ip1;
    document.getElementById('ter_mask1').value=data.ter_mask1;
    document.getElementById('ter_gateway1').value=data.ter_gateway1;
    if (data_query == 1) {
        xhr.open('get','/cgi-bin/hello.cgi?opt=version&function=get'+gettime());
        xhr.send(null);
    }
}

function first_main2(data)
{
    document.getElementById('ter_time').value=data.time;
    document.getElementById('device_id').innerHTML=data.device_id;
    document.getElementById('soft_version').innerHTML=data.soft_version;
    document.getElementById('hard_version').innerHTML=data.hard_version;
    document.getElementById('soft_pubdate').innerHTML=data.soft_pubdate;
    document.getElementById('cao_interval').value=data.cao_interval;
//    if (data_query == 1) {
//        xhr.open('get','/cgi-bin/hello.cgi?opt=data_source&function=get&meter_num=1'+gettime());
//        xhr.send(null);
//    }
}
function data_source(data)
{
    document.getElementById('meter_num').value=data.meter_num;
    document.getElementById('static_meter_num').innerHTML=data.meter_num;
    document.getElementById('device_number').value=data.device_number;
    document.getElementById('tongxunfangshi').value=data.tongxunfangshi;
    document.getElementById('baud_rate').value=data.baud_rate;
    document.getElementById('guiyue').value=data.guiyue;
    document.getElementById('jiexian').value=data.jiexian;
    if (data.not_set == 1)
        document.getElementById('not_set').style.display="block";
    else
        document.getElementById('not_set').style.display="none";
//    data_query = 0;
}

function meter_detail(data)
{
    document.getElementById('static_meterdata_num').innerHTML=data.meter_num;
    document.getElementById('static_meteraddr').innerHTML=data.device_number;
    if (data.not_set == 1) {
        document.getElementById('not_set2').style.display="block";
        document.getElementById('voltage').value='';
        document.getElementById('current').value='';
    }
    else
    {
        document.getElementById('not_set2').style.display="none";
        document.getElementById('voltage').value=(data.voltage*0.1).toFixed(1);
        document.getElementById('current').value=data.current;
    }
}

function master_sub()
{
    for(var i = 0;i<6;i++)
    {
        if(masterArr[i]){
            alert('format error');
            return;
        }
    }
    var url="/cgi-bin/hello.cgi?opt=master&function=set"+"&master_ip="+document.getElementById('master_ip').value;
    url=url+"&master_port="+document.getElementById('master_port').value;
    url=url+"&master_apn="+document.getElementById('master_apn').value;
    url=url+"&user="+document.getElementById('user').value;
    url=url+"&pwd="+document.getElementById('pwd').value;
    url=url+"&heartbeat="+document.getElementById('heartbeat').value+gettime();
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now applying please wait...";
    xhr.open('get',url);
    xhr.send(null);
}
function terminal_sub()
{
    for(var i = 0;i<3;i++)
    {
        if(terminalArr[i]){
            alert('format error');
            return;
        }
    }
    var url="/cgi-bin/hello.cgi?opt=terminal&function=set"+"&ter_ip="+document.getElementById('ter_ip1').value;
    url=url+"&ter_mask="+document.getElementById('ter_mask1').value;
    url=url+"&ter_gateway="+document.getElementById('ter_gateway1').value+gettime();
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now applying please wait...";
    xhr.open('get',url);
    xhr.send(null);
}
function meter_sub()
{
    for (var i = 0;i<2;i++) {
        if(meter_check[i]){
            alert('format error');
            return;
        }
    }
    var url="/cgi-bin/hello.cgi?opt=data_source&function=set"+"&meter_num="+document.getElementById('meter_num').value;
    url=url+"&device_number="+document.getElementById('device_number').value;
    url=url+"&tongxunfangshi="+document.getElementById('tongxunfangshi').value;
    url=url+"&baud_rate="+document.getElementById('baud_rate').value;
    url=url+"&guiyue="+document.getElementById('guiyue').value;
    url=url+"&jiexian="+document.getElementById('jiexian').value+gettime();
    document.getElementById('static_meter_num').innerHTML=document.getElementById('meter_num').value;
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now applying please wait...";
    document.getElementById('not_set').style.display="none";
    xhr.open('get',url);
    xhr.send(null);
    
}

function manage_sub()
{
    if(cao_check){
        alert('format error');
        return;
    }
    var url="/cgi-bin/hello.cgi?opt=manage&function=set"+"&flag=interval&cao_interval="+document.getElementById('cao_interval').value+gettime();
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now applying please wait...";
    xhr.open('get',url);
    xhr.send(null);
}

function date_sub()
{
    if(time_check){
        alert('format error');
        return;
    }
    var url="/cgi-bin/hello.cgi?opt=time&function=set"+"&time="+document.getElementById('ter_time').value+gettime();
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now applying please wait...";
    xhr.open('get',url);
    xhr.send(null);
}

function meter_query_sub()
{
    if(point_check){
        alert('format error');
        return;
    }
    var url="/cgi-bin/hello.cgi?opt=data_source&function=get"+"&meter_num="+document.getElementById('meter_num').value+gettime();
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now querying please wait...";
    xhr.open('get',url);
    xhr.send(null);
}



function meterdata_query()
{
    if(meterdata_check){
        alert('format error');
        return;
    }

    var url="/cgi-bin/hello.cgi?opt=meter_detail&function=get"+"&meter_num="+document.getElementById('meterdata_num').value+gettime();
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now querying please wait...";
    xhr.open('get',url);
    xhr.send(null);
}

function net_query()
{
    var url="/cgi-bin/hello.cgi?opt=main&function=get"+gettime();
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now querying please wait...";
    xhr.open('get',url);
    xhr.send(null);
}

function time_query()
{
    var url="/cgi-bin/hello.cgi?opt=time&function=get"+gettime();
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now querying please wait...";
    xhr.open('get',url);
    xhr.send(null);
}

function manage_query()
{
    var url="/cgi-bin/hello.cgi?opt=manage&function=get"+gettime();
    zhezhao.style.display="block";
    waitimg.style.display="block";
    set_info.innerHTML="Now querying please wait...";
    xhr.open('get',url);
    xhr.send(null);
}

var oloaded;
 function UpladFile() {
            var fileObj = document.getElementById("file1").files[0]; // js 获取文件对象
            if (!fileObj) {
                alert("file is null");
                return;
            }
            document.getElementById("info_upload").style.display="block";
            var url = "/cgi-bin/hello.cgi?opt=upload_file&function=get"+gettime(); // 接收上传文件的后台地址 
            
            var form = new FormData(); // FormData 对象
            form.append("file1", fileObj); // 文件对象
            
            xhr.open("post", url, true); //post方式，url为服务器请求地址，true 该参数规定请求是否异步处理。//请求完成
            xhr.onerror =  uploadFailed; //请求失败
            xhr.upload.onprogress = progressFunction;//【上传进度调用方法实现】
            xhr.upload.onloadstart = function(){//上传开始执行方法
                ot = new Date().getTime();   //设置上传开始时间
                oloaded = 0;//设置上传开始时，以上传的文件大小为0
            };
            xhr.send(form); //开始上传，发送form数据
        }
        function progressFunction(evt) {
            
             var progressBar = document.getElementById("bar");
             var percentageDiv = document.getElementById("percentageDiv");
      
             if (evt.lengthComputable) {//
         
                 progressBar.style.width = evt.loaded / evt.total * 100 + "%";
                 var tmp,units,upif;
                 tmp = evt.loaded;
                 if(tmp/1024>1){
                        tmp = tmp/1024;
                        units = 'k';
                 }
                    if(tmp/1024>1){
                        tmp = tmp/1024;
                        units = 'M';
                    }
                tmp = tmp.toFixed(1);
                     upif=tmp+units;
                tmp = evt.total;
                 if(tmp/1024>1){
                        tmp = tmp/1024;
                        units = 'k';
                 }
                    if(tmp/1024>1){
                        tmp = tmp/1024;
                        units = 'M';
                    }
                tmp = tmp.toFixed(1);
                     upif=upif+'/'+tmp+units;
                 percentageDiv.innerHTML = Math.round(evt.loaded / evt.total * 100) + "%   "+upif;
            }

            
        }
        //上传成功响应
        function uploadComplete(evt) {
         //服务断接收完文件返回的结果
             end_show("upload complete");
             document.getElementById("info_upload").style.display="none";
        }
        //上传失败
        function uploadFailed(evt) {
            end_show("upload failed");
             document.getElementById("info_upload").style.display="none";
        }
          //取消上传
        function cancleUploadFile(){
            xhr.abort();
        }

var masterArr = new Array(0,0,0,0,0,0);
var terminalArr = new Array(0,0,0);
var time_check = 0;
var meter_check = new Array(0,0);
var cao_check = 0;
var point_check = 0;
var meterdata_check = 0;

function text_check(ele)
{
    if (ele.getAttribute("id") == "master_ip") {
        if (!check_ip(ele.value)) {
            masterArr[0] = 1;
            document.getElementById("master_ip_err").style.display = "block";
        }else {
            masterArr[0] = 0;
            document.getElementById("master_ip_err").style.display = "none";
        }
    } else if (ele.getAttribute("id") == "master_port"){
        if (!checknum(ele.value,65535)) {
            masterArr[1] = 1;
            document.getElementById("master_port_err").style.display = "block";
        }else {
            masterArr[1] = 0;
            document.getElementById("master_port_err").style.display = "none";
        }
    } else if (ele.getAttribute("id") == "user"){
        if (ele.value.length>32) {
            masterArr[3] = 1;
            document.getElementById("user_err").style.display = "block";
        }else {
            masterArr[3] = 0;
            document.getElementById("user_err").style.display = "none";
        }
    } else if (ele.getAttribute("id") == "pwd"){
        if (ele.value.length>32) {
            masterArr[4] = 1;
            document.getElementById("pwd_err").style.display = "block";
        }else {
            masterArr[4] = 0;
            document.getElementById("pwd_err").style.display = "none";
        }
    } else if (ele.getAttribute("id") == "heartbeat"){
        if (!checknum(ele.value,1000)) {
            masterArr[5] = 1;
            document.getElementById("heartbeat_err").style.display = "block";
        }else {
            masterArr[5] = 0;
            document.getElementById("heartbeat_err").style.display = "none";
        }
    } else if (ele.getAttribute("id") == "ter_ip1"){
        if (!check_ip(ele.value)) {
            terminalArr[0] = 1;
            document.getElementById("ter_ip1_err").style.display = "block";
        }else {
            terminalArr[0] = 0;
            document.getElementById("ter_ip1_err").style.display = "none";
        }
    } else if (ele.getAttribute("id") == "ter_mask1"){
        if (!check_ip(ele.value)) {
            terminalArr[1] = 1;
            document.getElementById("ter_mask1_err").style.display = "block";
        }else {
            terminalArr[1] = 0;
            document.getElementById("ter_mask1_err").style.display = "none";
        }
    } else if (ele.getAttribute("id") == "ter_gateway1"){
        if (!check_ip(ele.value)) {
            terminalArr[2] = 1;
            document.getElementById("ter_gateway1_err").style.display = "block";
        }else {
            terminalArr[2] = 0;
            document.getElementById("ter_gateway1_err").style.display = "none";
        }
    } else if (ele.getAttribute("id") == "device_number"){
        if (ele.value.length!=12) {
            if (ele.value.length<12)
            {
                ele.value = PrefixInteger(ele.value, 12);
                meter_check[0]= 0;
                document.getElementById("device_number_err").style.display = "none";
            }else {
                meter_check[0] = 1;
                document.getElementById("device_number_err").style.display = "block";
            }
        }else {
            meter_check[0]= 0;
            document.getElementById("device_number_err").style.display = "none";
        }
    } else if (ele.getAttribute("id") == "cao_interval"){
        if (!checknum(ele.value,1000)) {
            cao_check = 1;
            document.getElementById("cao_interval_err").style.display = "block";
        }else {
            cao_check = 0;
            document.getElementById("cao_interval_err").style.display = "none";
        }
    } else if (ele.getAttribute("id") == "ter_time"){
        if (!check_datetime(ele.value)) {
            time_check = 1;
            document.getElementById("ter_time_err").style.display = "block";
        }else {
            time_check = 0;
            document.getElementById("ter_time_err").style.display = "none";
        }
    } else if (ele.getAttribute("id") == "meter_num"){
        if (!checknum(ele.value,1000)){
            point_check = 1;
            meter_check[1] = 1;
            document.getElementById("meter_num_err").style.display = "block";
        }else {
            point_check = 0;
            meter_check[1] = 0;
            document.getElementById("meter_num_err").style.display = "none";
        }
    } else if (ele.getAttribute("id") == "meterdata_num"){
        if (!checknum(ele.value,1000)){
            meterdata_check = 1;
            document.getElementById("meterdata_num_err").style.display = "block";
        }else {
            meterdata_check = 0;
            document.getElementById("meterdata_num_err").style.display = "none";
        }
    }


}

function PrefixInteger(num, n) {
        return (Array(n).join(0) + num).slice(-n);
}


function check_ip(str_ip)      
{  
   var re=/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;//正则表达式     
   if(re.test(str_ip))     
   {     
       if( RegExp.$1<256 && RegExp.$2<256 && RegExp.$3<256 && RegExp.$4<256)   
       return true;     
   }        
   return false;      
}  

function checknum(value,max) { 
　　if (value.length==0 || isNaN(value))
　　　　return false;
    if (parseInt(value) > max)
        return false;
    return true;
}

function check_datetime(str_date){
    var a = /^(\d{4})-(\d{2})-(\d{2})\/(\d{2}):(\d{2}):(\d{2})$/
    if (!a.test(str_date))
        return false;
    else 
        return true;
} 
