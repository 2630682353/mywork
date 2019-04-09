
// Plugin
;(function ( $, window, document, undefined ) {
    // CUSTOM VARIABLES

    var zoomables = new Array();
    var activeZoomable = undefined;
    var activeAnnotation = undefined;

    var imageInteraction = false;
    var interfaceInteraction = false;

    var windowScrollX = $(window).scrollLeft();
    var windowScrollY = $(window).scrollTop();
    var windowWidth = $(window).width();
    var windowHeight = $(window).height();

    // -END- CUSTOM VARIABLES

    // FUNCTIONS



    // -END- FUNCTIONS


    // Create the defaults once
    var annotatorPro = "annotatorPro",
        defaults = {
            frameWidth : "100%",
            frameHeight : "100%",
            maxZoom : "auto",
            navigator : false,
            navigatorImagePreview : false,
            fullscreen : false
        },
        annotation_defaults = {
            tint_color : "#000000",
            style : 1,
            popup_width : "auto",
            popup_height : "auto",
            popup_position : "top",
            content_type : "text", // or "custom-html"
            title : "Annotation",
            text : "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
            text_color : "#ffffff",
            html : "",
            id : "my-annotation-",
            spot_left : 0,
            spot_top : 0,
            spot_width : 44,
            spot_height : 44,
            spot_circle : true
        };

    // The actual plugin constructor
    function AnnotatorPro( element, options ) {
        this.element = element;

        this.options = $.extend( {}, defaults, options) ;

        this._defaults = defaults;
        this._name = annotatorPro;

        // CUSTOM PROPERTIES

        // general

        this.obj = undefined;
        this.obj_image = undefined;
        this.obj_content = undefined;
        this.img = undefined;

        this.frameWidth = 0;
        this.frameHeight = 0;
        this.contentWidth = 0;
        this.contentHeight = 0;

        this.frameOffsetLeft = 0;
        this.frameOffsetTop = 0;

        this.document_width = $(document).width();
        this.document_height = $(document).height();

        // zooming

        this.minZoom = 1;
        this.maxZoom = 4;
        this.currentZoom = 1;
        this.targetZoom = 1;

        this.zoomStep = 0.25;
        this.zoomSpeed = 0.15; // 1 = instant, 0.01 = slowest

        // moving

        this.defaultPosX = 0;
        this.defaultPosY = 0;
        this.targetPosX = 0;
        this.targetPosY = 0;
        this.currentPosX = 0;
        this.currentPosY = 0;

        this.dragOutOfBoundsX = 0;
        this.dragOutOfBoundsY = 0;

        this.intertia = 0.9; // 1 = endless, 0 = no intertia

        this.dragEventOriginX = 0;
        this.dragEventOriginY = 0;
        this.dragInitialPositionX = 0;
        this.dragInitialPositionY = 0;

        this.dragLastEventX = 0; // for velocity, intertia
        this.dragLastEventY = 0;
        this.dragMomentumX = 0;
        this.dragMomentumY = 0;
        this.dragMomentumCalculateTimer = 5;
        this.vx = 0;
        this.vy = 0;

        this.lastMomentumCalculateTime = 0;

        this.dragTimeout = undefined;
        this.zoomTimeout = undefined;

        // gestures
        this.lastTouchTime = 0;
        this.didDoubleTap = false;
        this.lastTouchX = 0;
        this.lastTouchY = 0;

        this.initialPinchDistance = 0;
        this.pinchDelta = 0;
        this.initialZoom = 0;
        this.lastZoom = 0;

        this.pinchZooming = false;
        this.pinchZoomOffsetX = 0;
        this.pinchZoomOffsetY = 0;

        this.dragging = false;

        // interface
        this.obj_interface = undefined;
        this.ui_hide_timeout = undefined;
        this.ui_visible = false;

        // navigator
        this.obj_navigator = undefined;
        this.obj_nav_window = undefined;
        this.navigatorWidth = 0;
        this.navigatorHeight = 0;

        this.navigator_dragging = false;

        this.nav_window_width = 0;
        this.nav_window_height = 0;

        // fullscreen
        this.obj_fullscreen = undefined;
        this.is_fullscreen = false;

        // annotations
        this.annotation_settings = this.options.annotations;
        this.annotations = new Array();

        // -END- CUSTOM PROPERTIES

        this.init();
    }

    AnnotatorPro.prototype = {

        init : function() {
            var self = this;

            // store reference
            self.id = zoomables.length;
            zoomables[self.id] = self;

            self.obj = $(self.element).parent();
            self.obj_content = self.obj.find(".ndd-drawables-container");
            self.init_annotations();

        },

        init_annotations : function() {
            var self = this;

            if (self.annotation_settings == undefined) return;

            if ($('#ndd-annotations-global-container').length == 0) {
                $('body').prepend('<div id="ndd-annotations-global-container"></div>');
            }

            var container = $('#ndd-annotations-global-container');

            for (var i=0; i<self.annotation_settings.length; i++) {
                var annotation = new NDD_Annotation(self.annotation_settings[i], self, container);
                self.annotations.push(annotation);
            }
        }

    };

    function NDD_Annotation(options, annotator, container) {
        this.options = $.extend( {}, annotation_defaults, options) ;

        this.annotator = annotator;
        this.id = 'ndd-annotation-popup-' + options.id;

        // objects
        this.obj_global_container = container;
        this.obj_parent = annotator.obj_content;
        this.obj_spot = undefined;
        this.obj_popup_container = undefined;
        this.obj_popup_box = undefined;
        this.obj_popup_content = undefined;
        this.obj_popup_arrow = undefined;
        this.obj_popup_buffer = undefined;

        // touch
        this.touch_start_time = 0;
        this.touch_x = 0;
        this.touch_y = 0;

        this.initialized_dimentions = false;
        this.is_visible;
        this.init();
    }
    NDD_Annotation.prototype = {
        init : function() {
            var self = this;

            // spot
            if (self.options.spot_circle) {
                self.obj_parent.append('<div id="'+self.id+'" class="ndd-drawable">'+self.options.num+'</div>');
            }else{
                self.obj_parent.append('<div class ="ndd-drawable-wrap" id="'+self.id+'"><div  class="ndd-drawable">'+self.options.num+'</div><div class=" ndd-drawable-active"></div></div>');
            }
            self.obj_spot = self.obj_parent.find('#' + self.id);

            self.obj_spot.css({
                left : self.options.spot_left,
                top : self.options.spot_top
            });

        }
    };

    $.fn[annotatorPro] = function ( options ) {
        return this.each(function () {

                $.data(this, "plugin_" + annotatorPro,
                new AnnotatorPro( this, options ));

        });
    };

})( jQuery, window, document );