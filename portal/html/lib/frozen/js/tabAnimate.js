var tabAnimate = function(obj){
        var tabNav = $(obj).parent();
        var tabContent = $(tabNav).next();
        $(tabNav).children().removeClass('current');
        $(obj).addClass('current');
        var index = $(obj).index();
        var tabContentLi = $(tabContent).children();

        //li 滚动效果
        $(tabContent).css({
            'transform' : 'translateX(-' +33.333333333333 * index+'%)',
            '-webkit-transform': 'translateX(-'+33.333333333333 * index+'%)',
            '-webkit-transition':'500ms linear'
        });

        //外框自适应
        $(tabContentLi).eq(index).css({
            'height':'auto'
        }).siblings().css({
            'height':'0'
        });
};


//移动设备基于屏幕宽度设置容器宽高
//height width 默认比例高度宽度
//需要等比设置高度的 元素 idString = “.adv”
//距离横向边框的 距离
function settingsAdv(crruentidth,defultHeight,defultWidth,idString,outDistace){
    var iScale = (crruentidth - outDistace) / defultWidth;
    $(idString).height(defultHeight * iScale).width(crruentidth-outDistace);
}