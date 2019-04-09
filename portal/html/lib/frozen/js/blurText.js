
// 元素失去焦点隐藏iphone的软键盘
function objBlurText(id,time){
    if(typeof id != 'string') throw new Error('objBlurText()参数错误');
    var obj = document.getElementById(id),
    time = time || 300,
    docTouchend = function(event){
        if(event.target!= obj){
            setTimeout(function(){
                obj.blur();
                document.removeEventListener('touchend', docTouchend,false);
            },time);
        }
    };
    if(obj){
        obj.addEventListener('focus', function(){
            document.addEventListener('touchend', docTouchend,false);
        },false);
    }else{
        throw new Error('objBlurText()没有找到元素');
    }
}
