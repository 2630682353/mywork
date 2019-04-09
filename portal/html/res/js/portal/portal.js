
/**
 * 跳转中间页，cookie存放 tmp
 */
//设置单图广告数据(logo)
function setSingleImg(target){
    target.find("img").attr("src", "../../../portal/res/img/mobile/def_top_left_logo.png");
}

//设置轮播图
function setCarouseImg(target,family){
    var html='';
    if(family=='mobile'){
        html+='<div class="item active">' +
            '<img  src="../../../portal/res/img/mobile/def_load.png" alt="...">' +
            '</div>'+
            '<div class="item">' +
            '<img  src="../../../portal/res/img/mobile/def_full_1.png" alt="...">' +
            '</div>';
    }else if(family=='pc'){
        html+='<div class="item active">' +
            '<img  src="../../../portal/res/img/mobile/def_load.png" alt="...">' +
            '</div>'+
            '<div class="item">' +
            '<img  src="../../../portal/res/img/mobile/def_full_1.png" alt="...">' +
            '</div>';
    }
    target.find('.carousel-inner').html(html);
    imgLoad(target,family,0);
}
//轮播图片的加载
function imgLoad(target,family,num){
    var t_img;             // 定时器
    var isLoad = true;    // 控制变量
    var imgHList = [];
    var imgWList = [];
    var picI,maxH,maxW,screenHeight;
    var screenWidth=window.screen.width;
    var imgList=target.find('.carousel-inner .item img');
    // 判断图片加载状况，加载完成后回调
    isImgLoad(function(){
        if(num == 1){           //有上传图片时
            //加载完成执行的方法,获取图片尺寸
            for(var j=0;j<imgList.length;j++){
                imgHList.push(imgList[j].height);
                imgWList.push(imgList[j].width);
            }
            maxH=Math.max.apply(null, imgHList);
            for(var k=0;k<imgList.length;k++){
                if(maxH == imgList[k].height){
                    maxW= imgList[k].width
                }
            }
            picI=maxW/maxH;
            screenHeight=screenWidth/picI;
            var contentTop = 70+screenHeight+"px";
            if(family=='mobile'){
                target.parent(".auth-footer").css({"height":screenHeight+'px',"top":"48px"});
                target.find('.carousel-inner').css({"height":screenHeight+'px'});
                target.find('.carousel-inner .item').css({"width":"100%","height":screenHeight+'px'});
                target.find('.carousel-inner .item img').css({"width":"100%","height":"auto","display":"block"});
                $('#mobile-auth-content').css({"top":contentTop});
            }
        }else if(num == 0){        //不上传图片，使用默认图片时
            var oneImgHeight = imgList.height();
            var oneContentTop=70+oneImgHeight+"px";
            if(family=='mobile'){
                target.parent(".auth-footer").css({"height":oneImgHeight+'px',"top":"50px"});
                target.find('.carousel-inner').css({"height":oneImgHeight+'px'});
                target.find('.carousel-inner .item').css({"height":oneImgHeight+'px'});
                target.find('.carousel-inner .item img').css({"width":"100%","height":"auto","display":"block"});
                $('#mobile-auth-content').css({"top":oneContentTop});
            }
        }
    });

    // 判断图片加载的函数
    function isImgLoad(callback){
        // 找到所有图偏，遍历处理
        imgList.each(function(){
            // 找到为0就将isLoad设为false，并退出each
            if(this.height === 0){
                isLoad = false;
                return false;
            }
        });
        if(isLoad){                  // 为true，没有发现为0的。加载完毕
            clearTimeout(t_img);     // 清除定时器
            callback();              // 执行回调
        }else{                       // 为false，如果找到没有加载完成的图，就调用定时器递归
            isLoad = true;
            t_img = setTimeout(function(){
                isImgLoad(callback);              // 递归扫描
            },100);
        }
    }
}
