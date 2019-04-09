	// VARIABLES
	var selected_drawable;
	var canvas;
	var active_object;
	var drawables = new Array();
	var canvasProperty = {width:0,height:0};
	var canvas_defaults = {
		frameWidth : 640,
		frameHeight : 480,
		maxZoom : "auto",
		navigator : false,
		navigatorImagePreview : false,
		fullscreen : false,
		formPC:true
	}

	var annotation_defaults = {
		id : "1",
		spot_left : 0,
		spot_top : 0,
		spot_width : 32,
		spot_height : 32,
		spot_circle : true
	};

	var g_hotInfo = {};//页面缓存热点信息

	// CLASSES
	function NDD_Drawable_Canvas(obj, width, height,canvas_settings, cb) {
		this.obj = $(obj);
		this.obj_img = undefined;
		this.img = new Image();
		this.width = width;
		this.height = height;

		this.obj_drawables_container = this.obj.find('.ndd-drawables-container');

		this.is_drawing = false;
		this.obj_temp = undefined;

		this.event_initial_x = 0;
		this.event_initial_y = 0;

		this.temp_pos_x = 0;
		this.temp_pos_y = 0;
		this.temp_width = 0;
		this.temp_height = 0;

		this.settings = $.extend({}, canvas_defaults,canvas_settings);

		// events
		this.init(cb);
	}
	NDD_Drawable_Canvas.prototype = {
		init : function(cb) {
			var self = this;

			canvas = self;
			self.obj_img = self.obj.find('img');

			if (self.width != 0 && self.height != 0) {
				self.obj.css({
					width : self.width,
					height : self.height
				});

				self.img.src = self.obj_img.attr('src');

				cb();
			} else {
				self.img.onload = function() {

					self.width = self.img.width;
					self.height = self.img.height;

					canvasProperty.height = self.img.height;
					canvasProperty.width = self.img.width;
					if (self.width > $('#panel-canvas').width()) {
						var scale = self.width / $('#panel-canvas').width();

						self.width = $('#panel-canvas').width();
						self.height = self.height / scale;
					}

					if (self.height > $('#panel-canvas').height()) {
						var scale = self.height / $('#panel-canvas').height();

						self.height = $('#panel-canvas').height();
						self.width = self.width / scale;
					}
					self.obj.css({
						width: self.width,
						height: self.height
					});

					cb();
				}

				self.img.src = self.obj_img.attr('src');

			}
		},
		handle_event : function(e) {
			var self = this;

			if (e.type == "mousedown") {

			}

			if (e.type == "mousemove") {
			}

			if (e.type == "mouseup") {
				if ($(e.target).hasClass('ndd-drawable-canvas') || $(e.target).hasClass('ndd-drawable-canvas-image')) {
					var x = e.pageX - self.obj.offset().left;
					var y = e.pageY - self.obj.offset().top;

					self.create_circle_spot(x, y);
				}
			}
		},
		start_drawing : function(pageX, pageY) {
			var self = this;

			self.obj_drawables_container.append('<div class="ndd-drawable-rect ndd-spot-rect ndd-rect-style-1" id="temp"><div class="ndd-icon-main-element"></div><div class="ndd-icon-border-element"></div></div>');
			self.obj_temp = $('#temp');

			self.temp_pos_x = pageX - self.obj.offset().left;
			self.temp_pos_y = pageY - self.obj.offset().top;

			self.obj_temp.css({
				"left" : self.temp_pos_x,
				"top" : self.temp_pos_y,
				"width" : 0,
				"height" : 0
			});

			self.event_initial_x = pageX;
			self.event_initial_y = pageY;
		},
		draw : function(pageX, pageY) {
			var self = this;

			self.temp_width = pageX - self.event_initial_x;
			self.temp_height = pageY - self.event_initial_y;

			if (self.temp_pos_x + self.temp_width > self.width) {
				self.temp_width = self.width - self.temp_pos_x;
			}

			if (self.temp_pos_y + self.temp_height > self.height) {
				self.temp_height = self.height - self.temp_pos_y;
			}

			self.obj_temp.css({
				"width" : self.temp_width,
				"height" : self.temp_height
			});
		},
		stop_drawing : function() {
			var self = this;

			var x = self.obj_temp.offset().left - self.obj.offset().left;
			var y = self.obj_temp.offset().top - self.obj.offset().top;
			var width = (self.obj_temp.width() < 32) ? 32 : self.obj_temp.width();
			var height = (self.obj_temp.height() < 32) ? 32 : self.obj_temp.height();

			if (width == 32 && height == 32) {
				self.create_circle_spot(x, y);
			} else {
				self.create_rect_spot(x, y, width, height);
			}

			self.obj_temp.remove();
			self.obj_temp = undefined;
		},
		create_circle_spot : function(x, y) {
			var self = this;

			var drawable = new NDD_Drawable(x, y, self.obj_drawables_container, self);
			return drawable;
		}
	};

	function NDD_Drawable(x, y, obj_parent, canvas) {
		this.is_rect = false;

		this.canvas = canvas;
		this.obj_parent = obj_parent;
		this.obj_visible = undefined;
		this.obj_active_area = undefined;
		this.obj = undefined;
		this.id = generate_annotation_id();
		this.num = generate_annotation_num();
		this.x = x;
		this.y = y;

		this.width = 32;
		this.height = 32;
		this.left = x - this.width/2;
		this.top = y - this.height/2;

		this.is_selected = false;
		this.is_moving = false;

		// moving
		this.event_initial_x = 0;
		this.event_initial_y = 0;
		this.initial_left = 0;
		this.initial_top = 0;

		// annotation
		this.annotation = undefined;

		this.settings = $.extend({}, annotation_defaults);
		this.settings.id = this.id;
		this.settings.num = this.num;
		this.settings.spot_left = this.left;
		this.settings.spot_top = this.top;
		this.settings.spot_width = this.width;
		this.settings.spot_height = this.height;
		this.settings.spot_circle = true;

		this.init();
	}
	NDD_Drawable.prototype = {
		init : function() {
			var self = this;

			drawables[self.id] = self;

			self.obj_parent.append('<div class="ndd-drawable" id="' +self.id+ '">'+self.settings.num+'</div>');
			self.obj = $('#' + self.id);

			self.constrain_position();

			self.obj.css({
				left : self.left,
				top : self.top,
				width : self.width,
				height : self.height
			});

			self.open_dialog();
		},
		handle_event : function(e) {
			var self = this;

			if (e.type == "mousedown") {

			}

			if (e.type == "mousemove") {
				if (!self.is_moving) {
					self.is_moving = true;

					if (!self.is_selected) {
						self.select();
					}

					self.start_moving(e.pageX, e.pageY);
				}
				if (self.is_moving) {
					self.move(e.pageX, e.pageY);
				}
			}

			if (e.type == "mouseup") {
				if (self.is_moving) {
					self.is_moving = false;
					self.end_moving();
				} else {
					self.select();
				}
			}
		},
		constrain_position : function() {
			var self = this;

			if (self.left > self.canvas.width - self.width) {
				self.left = self.canvas.width - self.width;
			}

			if (self.left < 0) {
				self.left = 0;
			}

			if (self.top > self.canvas.height - self.height) {
				self.top = self.canvas.height - self.height;
			}

			if (self.top < 0) {
				self.top = 0;
			}
		},
		open_dialog:function(){

			dialog(this);
		}
	};

	// FUNCTIONS

	function init_canvas(width, height,drawables,canvas_settings) {
		var settings = $.extend({}, canvas_defaults,canvas_settings);
		var tmp = new NDD_Drawable_Canvas($('.ndd-drawable-canvas'), width, height, canvas_settings, function () {

			if (settings.formPC) {        //没有描点不加载 并删除页面已经存在的描点 （只对于pc端）
				$(".ndd-drawable").remove();
				init_global_events();
			} else {
				init_mobile_events();
				var $drawable_canvas = $(".ndd-drawable-canvas");
				$drawable_canvas.controlPicture();
				$drawable_canvas.controlPictureByClick();
			}

			if(drawables){
				drawables.push({formPC: settings.formPC});
				generate_preview(drawables);
			}
		});
	}

	function init_global_events() {
		$(document).on('mousedown', function(e) {
			active_object = undefined;

			if ($(e.target).hasClass('ndd-drawable-canvas') || $(e.target).hasClass('ndd-drawable-canvas-image')) {
				e.preventDefault();

				active_object = canvas;
				active_object.handle_event(e);

				return false;
			}

			if ($(e.target).hasClass("ndd-drawable")){
				e.preventDefault();
				var arry=[{"spotName":"景点名称11","left":"70","top":"89","spotIntro":"景点介绍"}];
				dialog(arry);

				return false;
			}
		});

		$(document).on('mousemove', function(e) {
			if (active_object != undefined) {
				e.preventDefault();

				active_object.handle_event(e);

				return false;
			}
		});

		$(document).on('mouseup', function(e) {
			if (active_object != undefined) {
				active_object.handle_event(e);
			}

			active_object = undefined;

		});

	}
	function init_mobile_events(){
		$(document).on('touchend', function(e) {
			active_object = undefined;
			var $target = $(e.target);
			if ( $target.hasClass("ndd-drawable")){
				e.preventDefault();
				resetAllDrawable();
				$target.addClass("disableDrawable");
				$target.next(".ndd-drawable-active").addClass("activeDrawable");
				var $dialogObj = $(".voice-description");
				var hotIdEl = $target.parent().attr("id");
				var hotId = hotIdEl.split("ndd-annotation-popup-")[1];
				g_hotInfo = hotInfo(hotId);
				initialDialog_mobile(g_hotInfo,$dialogObj);
				$dialogObj.show();
			}
			if ($target.hasClass("vioce-img-click")) {//暂停音乐
				e.preventDefault();
				$target.removeClass("vioce-img-click");
				pauseMuisc();
			} else if ($target.hasClass("vioce-img-unclick")) {//播放音乐
				e.preventDefault();
				$target.addClass("vioce-img-click");
				playMusic($target.attr("title"));
			}
			if($target.hasClass("more")){
				toHotInfo();
			}
		});
		$(".ndd-drawable-bg").tap(function(e){
			e.preventDefault();
			resetAllDrawable();
		});
		$(".ndd-drawable-canvas-image").tap(function(e){
			e.preventDefault();
			resetAllDrawable();
		});
	}

	function generate_annotation_id() {
		return "my-annotation-" + Math.floor(Math.random() * 100000) + 1;
	}
	function generate_annotation_num(){
		annotation_num = annotation_num + 1;
		return annotation_num;
	}

	function dialog(drawable){
		layer.open({
			type: 2,
			skin: 'top-layer ', //样式类名
			title:'编辑景点',
			area: ['682px', '430px'],
			btn:['确定','取消'],
			fix: true, //不固定
			content: 'dialog.html',
			success:function(layero,index){
				var body = layer.getChildFrame('body', index);
				$(body).find(".scenery-body .coordinate").text("("+drawable.left+","+drawable.top+")");
				$(body).find(".scenery-body .spotName").val(drawable[0].spotName);
				$(body).find(".scenery-body .coordinate").text("("+drawable[0].left+","+drawable[0].top+")");
				$(body).find(".scenery-body .spotIntro").val(drawable[0].spotIntro);
			},
			yes:function(index){
				//点击确认按钮触发事件
			},
			cancel:function(layer_index){
				layer.close(layer_index);
			}
		});
	}
	function initialDialog_mobile(mapData,$dialogObj){
		var $voice = $dialogObj.find(".vioce ");
        var orDrawableId = $dialogObj.attr("data_id");
        if(orDrawableId == mapData.hot_id && $voice.hasClass("vioce-img-click")){//若为之前已经在播放的坐标点音频则不暂停 ，否则重置
            return;
        }
        $dialogObj.attr("data_id", mapData.hot_id);//记录当前点击的坐标点id
        $dialogObj.find("h3").text(mapData.hot_name);
        $dialogObj.find("p").text(mapData.hot_introduce);
        $voice.attr("title", mapData.voice);
		pauseAllMusic();
	}
	function resetDialogPosition($dialogObj){
		var $canvas = $(".ndd-drawable-canvas");
		var canvasWidth=$canvas.width();
		var canvasHeight=$canvas.height();
		var left=parseFloat(($dialogObj.parent().css("left").split("px")[0]));
		var top=parseFloat(($dialogObj.parent().css("top").split("px")[0]));
		var right=canvasWidth-left;
		var bottom=canvasHeight-top;
		var topDialogPos=top+90;
		var height=$dialogObj.height();
		if(left > right){
			$dialogObj.addClass("voice-description_left");
		}
		if(bottom < height) {
			if(topDialogPos > height){
				$dialogObj.addClass("voice-description_top");
				return;
			}
			$dialogObj.addClass("voice-description_bottom");
		}
	}
	function playMusic(src) {
		var audio = document.getElementById("audio");
		if( $(audio).attr("src") == "" ||  $(audio).attr("src") != src){
			$(audio).attr("src", src);
		}
		audio.addEventListener("loadstart", function()
			{
				$(".vioce").addClass("vioce-img-load");
			}
		);
		audio.addEventListener("canplay", function()
			{
				$(".vioce").removeClass("vioce-img-load");
				$(".vioce").addClass("vioce-img-click");
			}
		);
		audio.play();
		$(audio).on('ended', function () {//音乐播放结束
			$(".vioce").removeClass("vioce-img-click");
		});
	}
	function pauseMuisc(){
		var audio = document.getElementById("audio");
		audio.pause();
	}

	function pauseAllMusic(){
		$(".vioce").removeClass("vioce-img-click");
		var $audios = $("audio");
		var len = $audios.length;
		for(var i =0 ;i <len ; i++){
			$audios.eq(i)[0].pause();
			$audios.eq(i).removeAttr("src");
		}
	}

		function generate_preview(annotations) {

			var frameWidth = (canvas.settings.frameWidth == "auto") ? '100%' : canvas.settings.frameWidth;
			var frameHeight = (canvas.settings.frameHeight == "auto") ? '100%' : canvas.settings.frameHeight;
			var maxZoom = (canvas.settings.maxZoom == "auto") ? 'auto' : canvas.settings.maxZoom;
			var navigator = canvas.settings.navigator;
			var navigatorImagePreview = canvas.settings.navigatorImagePreview;
			var fullscreen = canvas.settings.fullscreen;

			var len = annotations.length - 1;
			if(len < 0){
				return;
			}
			var formPc = annotations[len].formPC;
			var scale = 1;
			if(formPc != "" || formPc != undefined){
				annotations.pop();
				len = len - 1;
				scale = getScale(canvas.width,canvas.height);
			}
			//var scale = getScale(canvas.width,canvas.height);
			console.log("{annotations:"+annotations+",scale:"+scale+"}");
			for (var i = 0; i <= len; i++) {
				annotations[i] = $.extend({}, annotation_defaults,annotations[i]);

				var spot_left = toFixed(annotations[i].hot_x / canvas.width * 100, 2) + '%';
				var spot_top = toFixed(annotations[i].hot_y / canvas.height * 100, 2) + '%';
				var spot_circle = annotations[i].spot_circle
				if(!formPc){
					spot_circle = false;
				}

				if (!spot_circle) {//移动端
					spot_left = toFixed((parseFloat(annotations[i].hot_x) + 16) / canvas.width * scale * 100, 2) + '%';
					spot_top = toFixed((parseFloat(annotations[i].hot_y) + 16) / canvas.height * scale * 100, 2) + '%';
				}
				console.log("["+annotations[i].hot_id+","+annotations[i].hot_x+","+annotations[i].hot_y+","+spot_left+","+spot_top+"]");
				var spot_width = 32;
				var spot_height = 32;

				if (!spot_circle) {//移动端
					spot_width = toFixed(annotations[i].hot_x / canvas.width * 100, 2) + '%';
					spot_height = toFixed(annotations[i].hot_y / canvas.height * 100, 2) + '%';
				}

				annotations[i] = {
					id: annotations[i].hot_id,
					spot_left: spot_left,
					spot_top: spot_top,
					spot_width: spot_width,
					spot_height: spot_height,
					spot_circle:spot_circle,
					num:i+1
				}
			}

			$('#panel-canvas').annotatorPro({
				frameWidth: frameWidth,
				frameHeight: frameHeight,
				maxZoom: maxZoom,
				navigator: navigator,
				navigatorImagePreview: navigatorImagePreview,
				fullscreen: fullscreen,
				annotations: annotations
			});
		}
	function getScale(width,height){
		console.log("width:"+width+",height:"+height+",canvasProperty.width:"+canvasProperty.width+",canvasProperty.height:"+canvasProperty.height);

		var scale = 1;
		if (canvasProperty.width > 736) {
			scale = width / 736;
			canvasProperty.height = canvasProperty.height / (canvasProperty.width/ 736);
		}
		if (canvasProperty.height > 480) {
			scale = height / 480;
		}
		if(canvasProperty.width <= 736 && canvasProperty.height <= 480){
			scale = width / canvasProperty.width;
		}
		return scale;
	}

	function resetAllDrawable(){
		$(".ndd-drawable").removeClass("disableDrawable");
		$(".ndd-drawable-active").removeClass("activeDrawable");
		var $voice = $(".voice-description");
		$voice.hide();
		$voice.removeClass("voice-description_left voice-description_top voice-description_bottom");
	}

		function toFixed(number, precision) {
			var multiplier = Math.pow(10, precision + 1),
				wholeNumber = Math.floor(number * multiplier);
			return Math.round(wholeNumber / 10) * 10 / multiplier;
		}

































