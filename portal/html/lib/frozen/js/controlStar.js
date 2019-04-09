
/*lightStarNum : 点亮星星的个数*/
/*starId : 一组星星的id 不允许重复*/

/*lightStarNum : 点亮星星的个数 存在小数时为半颗星*/
/*starId : 一组星星的id 不允许重复*/
function showStar(lightStarNum , starId){
    var starObj = $("div[id = '"+starId+"']");
    var starList = $("div" ,starObj);
    if(starList.length){
        var re =  /^[1-9]+[0-9]*]*$/;
        for(var i =0;i< lightStarNum;i++)
        {
            if(starList[i])
            {
                if(!re.test(lightStarNum))
                {
                    if(i > lightStarNum -1 )
                    {
                        $(starList[i]).addClass("icon-half-yellow");
                    }
                    else
                    {
                        $(starList[i]).addClass("icon-yellow");
                    }
                }
                else
                {
                    $(starList[i]).addClass("icon-yellow");
                }
            }
        }
    }
}

/*星级评价统计*/
(function($){
    $.fn.showStarStatistics = function(settings){
        var defaultSettings = {
            starCommPerData : [{name:'五星',percent:'0.8'},{name:'四星',percent:'0.1'},{name:'三星',percent:'0.05'},{name:'二星',percent:'0.03'},{name:'一星',percent:'0.02'}]
        }
        settings = $.extend(true, {}, defaultSettings, settings);
        return this.each(function(){
            var s = settings;
            var starStatistics =$(".starStatistics");

            var starCommPerData = s.starCommPerData;
                var num = starCommPerData.length;
                for(var i = 0; i < num; i++){
                    var starLi = $('<li><p></p></li>');
                    $('p',starLi).text(starCommPerData[i].name);
                    var perBar = $('<div><div class="starValue"></div><div class="starNull"></div><span class="percent"></span></div>');
                    $('.starValue',perBar).css({
                        width:(starCommPerData[i].percent * 100/1).toFixed(0) + '%'
                    });
                    $('.starNull',perBar).width(((1 - starCommPerData[i].percent)  * 100).toFixed(0) + '%');
                    $('span',perBar).text((starCommPerData[i].percent * 100).toFixed(0) + '%');

                    starLi.append(perBar);
                    starStatistics.append(starLi);
                }
        })
    }
})(Zepto);

var defaultIndex=0;
function doRate(){
    $(".stars div").on('click',function(){
        var index = $(this).index();
        var stars = $(".stars div");
        if(defaultIndex == index){
            stars.eq(index).removeClass("icon-yellow");
            defaultIndex -=1;
        }else{
        	stars.removeClass("icon-yellow");
        	if(index == 0)stars.eq(0).addClass("icon-yellow");
        	for(var i = 0 ; i<= index ; i++){
                stars.eq(i).addClass("icon-yellow");
            }
        	defaultIndex = index;
        }
        
    });
}

