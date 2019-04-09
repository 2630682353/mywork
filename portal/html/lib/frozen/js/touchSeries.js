
(function($,document){
    'use strict';
    $.fn.controlPicture = function(){
        return new Control(this);
    };
    var Control = function(element){
        var me = this;
        me.$element = $(element);
        me.init();
    };
    // 初始化
    Control.prototype.init = function(){
        var me = this;
        var $zoomRange = $("#controlPictureContainer");
        if(!$zoomRange){
            $zoomRange = $(document);
        }
        me._minHeight =$zoomRange.height();
        me._minWidth =$zoomRange.width();
        me._initialWidth = me.$element.width();
        me._initialHeight = me.$element.height();
        me._maxHeight = me._initialHeight * 1.4;
        me._maxWidth = me._initialWidth * 1.4;

        // 绑定触摸
        me.$element.on('touchstart',function(e){
            fnTouches(e);
            fnTouchstart(e, me);
        });
        me.$element.on('touchmove',function(e){
            fnTouches(e, me);
            fnTouchmove(e, me);
        });
        me.$element.on('touchend',function(){
            fnTouchend(me);
        });
    };
    // touches
    function fnTouchstart(e, me) {
        me._startY = e.touches[0].pageY;
        me._startX = e.touches[0].pageX;

        initialLastStatus(me);

        if(e.touches.length == 2){//2根手指同时触碰屏幕
            me._startDistance = distance(me._startX,me._startY,e.touches[1].pageX,e.touches[1].pageY);
        }
    }
    // touchmove
    function fnTouchmove(e, me) {

        /*手指目前的位置 - 手指放下的位置 = 移动了的位置*/
        me._curY = e.touches[0].pageY;
        me._curX = e.touches[0].pageX;
        if(e.touches.length == 1){
            movePic(me);
        }else if(e.touches.length == 2){
            me._curXS = e.touches[1].pageX;
            me._curYS = e.touches[1].pageY;
            setZoomMatrix(me);//控制图片缩放
        }
    }
    // touchend
    function fnTouchend(me){
       /* if(me._matrixCurY > 2){//大于2倍比例
           /!* me.$element.css({
                'transform': 'matrix(2,0,0,2,'+me._positionX+','+me._positionY+')',
                '-webkit-transform': 'matrix(2,0,0,2,'+me._positionX+','+me._positionY+')'
            });*!/
            fnTransform(me.$element,2,2,me._positionX,me._positionY);
        }else if(me._matrixCurY < 1){//小于1倍比例
           /!* me.$element.css({
                'transform': 'matrix(1,0,0,1,'+me._positionX+','+me._positionY+')',
                '-webkit-transform': 'matrix(1,0,0,1,'+me._positionX+','+me._positionY+')'
            });*!/
            fnTransform(me.$element,1,1,me._positionX,me._positionY);
        }*/
        if(me.$element.height() < me._minHeight && me.$element.width() < me._minWidth){
                me.$element.width(me._initialWidth);
                me.$element.height(me._initialHeight);
        }
        if(me.$element.height() > me._maxHeight && me.$element.width() > me._maxWidth){
            me.$element.width(me._maxWidth);
            me.$element.height(me._maxHeight);
        }
    }
    function canNotMove(me){
        //if(me._width <= me._minWidth && me._height <= me._minHeight) {
        //    return true;
        //}
        var topPos = 110;
        var botPos = -100;
        if(me._height > me._minHeight){
            botPos =  -(parseInt(me._height) + 110 - parseInt(me._minHeight));
        }
        var leftPos = 110;
        var rightPos = -110;
        if(me._width > me._minWidth){
            rightPos =  -(parseInt(me._width) + 110 - parseInt(me._minWidth));
        }
        if(me._moveX > leftPos){
            if(me._moveY > topPos){
                fnTransform(me.$element,me._matrixCurX,me._matrixCurY,leftPos,topPos);
                return true;
            }else if(me._moveY <= botPos){
                fnTransform(me.$element,me._matrixCurX,me._matrixCurY,leftPos,botPos);
                return true;
            }
            fnTransform(me.$element,me._matrixCurX,me._matrixCurY,110,me._moveY);
            return true;
        }else if(me._moveX <= rightPos){
            if(me._moveY > topPos){
                fnTransform(me.$element,me._matrixCurX,me._matrixCurY,rightPos,topPos);
                return true;
            }else if(me._moveY <= botPos){
                fnTransform(me.$element,me._matrixCurX,me._matrixCurY,rightPos,botPos);
                return true;
            }
            fnTransform(me.$element,me._matrixCurX,me._matrixCurY,rightPos,me._moveY);
            return true;
        }else{
            if(me._moveY > topPos){
                fnTransform(me.$element,me._matrixCurX,me._matrixCurY,me._moveX,topPos);
                return true;
            }else if(me._moveY <= botPos){
                fnTransform(me.$element,me._matrixCurX,me._matrixCurY,me._moveX,botPos);
                return true;
            }
        }

        return false;

    }

    function movePic(me){
        me._moveY = me._curY - me._startY;
        me._moveX = me._curX - me._startX;
        //移动后图片坐标
        me._moveY += me._positionY;
        me._moveX += me._positionX;
        if(canNotMove(me)){
            return;
        }
       /* me.$element.css({
            'transform': 'matrix('+me._matrixCurX+',0,0,'+ me._matrixCurY+','+me._moveX+','+me._moveY+')',
            '-webkit-transform': 'matrix('+me._matrixCurX+',0,0,'+ me._matrixCurY+','+me._moveX+','+me._moveY+')'
        });*/
        fnTransform(me.$element,me._matrixCurX,me._matrixCurY,me._moveX,me._moveY);

    }
    /**
     *  计算两个手指间的距离
     */
    function distance(x1,y1,x2,y2) {
        var dx = x2 - x1;
        var dy = y2 - y1;
        /** 使用勾股定理返回两点之间的距离 */
        return Math.sqrt(dx * dx + dy * dy);
    }
    function setZoomMatrix(me){
        var _curDistance =  distance(me._curX,me._curY,me._curXS,me._curYS);
        var per = _curDistance / me._startDistance;//缩放倍数

        me._HeightCur = me._height * per;
        me._withCur = me._width * per;

        me.$element.css({height:me._HeightCur,width:me._withCur});
     /*   me._matrixCurX = me._matrixX * per;
        me._matrixCurY = me._matrixY * per ;*/
       /* me.$element.css({
            'transform': 'matrix('+me._matrixCurX+',0,0,'+ me._matrixCurY+','+me._positionX+','+me._positionY+')',
            '-webkit-transform': 'matrix('+me._matrixCurX+',0,0,'+ me._matrixCurY+','+me._positionX+','+me._positionY+')'
        });*/
/*
        fnTransform(me.$element,me._matrixCurX,me._matrixCurY,me._positionX,me._positionY);
*/
    }

})(window.Zepto || window.jQuery);
function fnTransform(obj,_matrixX,_matrixY,_positionX,_positionY){
    obj.css({
        'transform': 'matrix('+_matrixX+',0,0,'+ _matrixY+','+_positionX+','+_positionY+')',
        '-webkit-transform': 'matrix('+_matrixX+',0,0,'+ _matrixY+','+_positionX+','+_positionY+')'
    });
}
function initialLastStatus(me){
    var trans = me.$element.css("-webkit-transform");
    var transArray = trans.split(",");
    var poX = transArray[4];//坐标x
    me._positionX = parseFloat(poX);
    var poY = transArray[5];
    poY = poY.match(/-*\d+/g);//坐标y
    me._positionY = parseFloat(poY);

    var _matrixY = transArray[3];
    me._matrixY = parseFloat(_matrixY);//x方向的放大倍数

    var _matrixX = transArray[0].trim().split("matrix(")[1];
    me._matrixX = parseFloat(_matrixX);

    //防止滑动的时候放大缩小变回最初状态
    me._matrixCurY = me._matrixY;
    me._matrixCurX = me._matrixX;


    var height = me.$element.css("height");
    var width = me.$element.css("width");
    height = height.split("px")[0];
    width = width.split("px")[0];
    me._height = height;
    me._width = width;
}
function fnTouches(e){
    e.preventDefault();
    if(!e.touches){
        e.touches = e.originalEvent.touches;
    }
}


//模拟滚动效果
(function($) {
    'use strict';
    var visibleHeight;
    $.fn.moveSection = function () {
        return new Move(this);
    };
    var Move = function (element) {
        var me = this;
        me.$element = $(element);
        visibleHeight = $(".container").height() - 97 -45 -  me.$element.height();//超过可视范围的距离

        me.init();
    };
    // 初始化
    Move.prototype.init = function () {
        var me = this;

        // 绑定触摸
        me.$element.on('touchstart', function (e) {
            fnTouches(e);
            fnTouchstart(e, me);
        });
        me.$element.on('touchmove', function (e) {
            fnTouches(e, me);
            fnTouchmove(e, me);
        });
        me.$element.on('touchend', function () {
            fnTouchend(me);
        });

        function fnTouchstart(e, me) {
            me.$element.removeClass("moveTransition");
            me._startY = e.touches[0].pageY;

            initialLastStatus(me);
        }
        // touchmove
        function fnTouchmove(e, me) {

            /*手指目前的位置 - 手指放下的位置 = 移动了的位置*/
            me._curY = e.touches[0].pageY;
            me._moveY = (me._curY - me._startY) * 1.5;


            if( me._moveY > 0){//向下滑动
                var poY = - me._positionY;//向下剩余可滑动距离
                if(me._positionY == 0){//内容已置顶
                    return;
                }else if(poY <  me._moveY){//滑动距离大于可滑动距离取最小滑动距离
                    fnTransform(me.$element,1,1,0,0);
                    return;
                }
            }


            if(me._moveY < 0){//向上滑动
                if ( visibleHeight >= 0 ) {//内容在可视框以内
                    return;
                } else{//内容超过可视框
                    console.log("visibleHeight:"+visibleHeight);

                    console.log("me._moveY + me._positionY:"+(me._moveY + me._positionY));
                     if( me._positionY <= visibleHeight){//已经到达底部
                         return;
                     }else if(visibleHeight >  (me._moveY + me._positionY)){
                        fnTransform(me.$element, 1, 1, 0, visibleHeight);
                         return;
                     }
                }
            }
            me._moveY += me._positionY;




            fnTransform(me.$element,1,1,0,me._moveY);
        }
        // touchend
        function fnTouchend(me){
            me.$element.addClass("moveTransition");
        }
    };
})(window.Zepto || window.jQuery);



/*点击触发放大缩小*/
(function( $ ,document) {
    'use strict';
    var curScale = 1;
    var defaultSetting = {
        "maxScale":1.4,
        "minScale":1
    };
    $.fn.controlPictureByClick = function (settings) {
        settings = $.extend({},defaultSetting,settings);
        return new Control(this,settings);
    };
    var Control = function (element,settings) {
        var me = this;
        me.$element = $(element);
        me._height = me.$element.height();
        me._width = me.$element.width();
        var $zoomRange = $("#controlPictureContainer");
        if(!$zoomRange){
            $zoomRange = $(document);
        }
        me._minHeight =$zoomRange.height();
        me._minWidth =$zoomRange.width();
        me._settings = settings;
        me.init();
    };
    // 初始化
    Control.prototype = {
        init: function (){
            var self = this;
            $("#zoomIn").on("touchend", function (e) {
                e.preventDefault();
                self.zoomInView();
            });
            $("#zoomOut").on("touchend", function (e) {
                e.preventDefault();
                self.zoomOutView();
            });
        },
        /*放大*/
        zoomInView:function(){
            curScale = Math.round((this.$element.height()/this._height)*10)/10;
            if(curScale >= this._settings.maxScale){//超过最大比例就不能再操作
                return;
            }
            curScale = Math.round((curScale + 0.1)*10)/10;
            this.resetView();
        },
        /*缩小*/
        zoomOutView:function(){
            curScale = Math.round((this.$element.height()/this._height)*10)/10;
            if(curScale <= this._settings.minScale){//超过最小放大比例就不能再操作
                return;
            }
            curScale = Math.round((curScale - 0.1)*10)/10;
            this.resetView();
        },
        resetView:function(){
            this.$element.height(this._height * curScale);
            this.$element.width(this._width * curScale);
        }
    };

})(window.Zepto || window.jQuery);

(function( w, $, undefined ){

    // handling flag is true when an event sequence is in progress (thx androood)
    w.tapHandling = false;
    var untap = function( $els ){
        return $els.off( ".fz.tap" );
    };
    var tap = function( $els ){
        return $els.each(function(){

            var $el = $( this ),
                resetTimer,
                startY,
                startX,
                cancel,
                scrollTolerance = 10;

            function trigger( e ){
                $( e.target ).trigger( "tap", [ e, $( e.target ).attr( "href" ) ] );
                e.stopPropagation();
            }

            function getCoords( e ){
                var ev = e.originalEvent || e,
                    touches = ev.touches || ev.targetTouches;

                if( touches ){
                    return [ touches[ 0 ].pageX, touches[ 0 ].pageY ];
                }
                else {
                    return null;
                }
            }

            function start( e ){
                if( e.touches && e.touches.length > 1 || e.targetTouches && e.targetTouches.length > 1 ){
                    return false;
                }

                var coords = getCoords( e );
                startX = coords[ 0 ];
                startY = coords[ 1 ];
            }

            // any touchscroll that results in > tolerance should cancel the tap
            function move( e ){
                if( !cancel ){
                    var coords = getCoords( e );
                    if( coords && ( Math.abs( startY - coords[ 1 ] ) > scrollTolerance || Math.abs( startX - coords[ 0 ] ) > scrollTolerance ) ){
                        cancel = true;
                    }
                }
            }

            function end( e ){
                clearTimeout( resetTimer );
                resetTimer = setTimeout( function(){
                    w.tapHandling = false;
                    cancel = false;
                }, 1000 );

                // make sure no modifiers are present. thx http://www.jacklmoore.com/notes/click-events/
                if( ( e.which && e.which > 1 ) || e.shiftKey || e.altKey || e.metaKey || e.ctrlKey ){
                    return;
                }

                e.preventDefault();

                // this part prevents a double callback from touch and mouse on the same tap

                // if a scroll happened between touchstart and touchend
                if( cancel || w.tapHandling && w.tapHandling !== e.type ){
                    cancel = false;
                    return;
                }

                w.tapHandling = e.type;
                trigger( e );
            }

            $el
                .bind( "touchstart.fz.tap MSPointerDown.fz.tap", start )
                .bind( "touchmove.fz.tap MSPointerMove.fz.tap", move )
                .bind( "touchend.fz.tap MSPointerUp.fz.tap", end )
                .bind( "click.fz.tap", end );
        });
    };



    // use special events api
    if( $.event && $.event.special ){
        $.event.special.tap = {
            add: function( handleObj ) {
                tap( $( this ) );
            },
            remove: function( handleObj ) {
                untap( $( this ) );
            }
        };
    }
    else{
        // monkeybind
        var oldOn = $.fn.on,
            oldOff = $.fn.off;
        $.fn.on = function( evt ){
            if( /(^| )tap( |$)/.test( evt ) ){
                untap(this);
                tap( this );
            }
            return oldOn.apply( this, arguments );
        };
        $.fn.off = function( evt ){
            if( /(^| )tap( |$)/.test( evt ) ){
                untap( this );
            }
            return oldOff.apply( this, arguments );
        };

    }
    $.fn.tap=function(callback){
        $(this).on("tap",callback);
    }

}( this, jQuery|| Zepto ));

