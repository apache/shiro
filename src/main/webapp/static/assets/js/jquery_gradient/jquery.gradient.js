/* Copyright (c) 2006 Brandon Aaron (http://brandonaaron.net)
 * Dual licensed under the MIT (http://www.opensource.org/licenses/mit-license.php) 
 * and GPL (http://www.opensource.org/licenses/gpl-license.php) licenses.
 *
 * Color functions from Steve's Cross Browser Gradient Backgrounds v1.0 (steve@slayeroffice.com && http://slayeroffice.com/code/gradient/)
 *
 * $LastChangedDate: 2007-06-26 19:52:18 -0500 (Tue, 26 Jun 2007) $
 * $Rev: 2163 $
 *
 * Version 1.0
 */
(function($) {

/**
 * Adds a gradient to the background of an element.
 *
 * @example $('div').gradient({ from: '000000', to: 'CCCCCC' });
 *
 * @param Map options Settings/options to configure the gradient.
 * @option String from The hex color code to start the gradient with.
 * 		By default the value is "000000".
 * @option String to The hex color code to end the gradient with.
 * 		By default the value is "FFFFFF".
 * @option String direction This tells the gradient to be horizontal
 *      or vertical. By default the value is "horizontal".
 * @option Number length This is used to constrain the gradient to a
 *      particular width or height (depending on the direction). By default
 *      the length is set to null, which will use the width or height
 *      (depending on the direction) of the element.
 * @option String position This tells the gradient to be positioned
 *      at the top, bottom, left and/or right within the element. The
 *      value is just a string that specifices top or bottom and left or right.
 *      By default the value is 'top left'.
 *
 * @name gradient
 * @type jQuery
 * @cat Plugins/gradient
 * @author Brandon Aaron (brandon.aaron@gmail.com || http://brandonaaron.net)
 */
$.fn.gradient = function(options) {
	options = $.extend({ from: '000000', to: 'ffffff', direction: 'horizontal', position: 'top', length: null }, options || {});
	var createColorPath = function(startColor, endColor, distance) {
		var colorPath = [],
		    colorPercent = 1.0,
			distance = (distance < 100) ? distance : 100;
		do {
			colorPath[colorPath.length] = setColorHue(longHexToDec(startColor), colorPercent, longHexToDec(endColor));	
			colorPercent -= ((100/distance)*0.01);
		} while (colorPercent>0);
		return colorPath;
	},
	setColorHue = function(originColor, opacityPercent, maskRGB) {
		var returnColor = [];
		for (var i=0; i<originColor.length; i++)
			returnColor[i] = Math.round(originColor[i]*opacityPercent) + Math.round(maskRGB[i]*(1.0-opacityPercent));
		return returnColor;
	},
	longHexToDec = function(longHex) {
		return new Array(toDec(longHex.substring(0,2)),toDec(longHex.substring(2,4)),toDec(longHex.substring(4,6)));
	},
	toDec = function(hex) {
		return parseInt(hex,16);
	};
	return this.each(function() {
		var $this = $(this), width = $this.innerWidth(), height = $this.innerHeight(), x = 0, y = 0, w = 1, h = 1, html = [],
		    length = options.length || (options.direction == 'vertical' ? width : height),
		    position = (options.position == 'bottom' ? 'bottom:0;' : 'top:0;') + (options.position == 'right' ? 'right:0;' : 'left:0;'), 
		    colorArray = createColorPath(options.from, options.to, length);
		
		if (options.direction == 'horizontal') {
			h = Math.round(length/colorArray.length) || 1;
			w = width;
		} else {
			w = Math.round(length/colorArray.length) || 1;
			h = height;
		}
		
		html.push('<div class="gradient" style="position: absolute; ' + position + ' width: ' + (options.direction == 'vertical' ? length+"px" : "100%") +'; height: ' + (options.direction == 'vertical' ? "100%" : length+"px") + '; overflow: hidden; z-index: 0; background-color: #' + (options.position.indexOf('bottom') != -1 ? options.from : options.to) + '">');
		for(var i=0; i<colorArray.length; i++) {
			html.push('<div style="position:absolute;z-index:1;top:' + y + 'px;left:' + x + 'px;height:' + (options.direction == 'vertical' ? "100%" : h+"px") + ';width:' + (options.direction == 'vertical' ? w+"px" : "100%") + ';background-color:rgb(' + colorArray[i][0] + ',' + colorArray[i][1] + ',' + colorArray[i][2] + ');"></div>');
			options.direction == 'vertical' ? x+=w : y+=h;
			
			if ( y >= height || x >= width) break;
		}
		html.push('</div>');
		
		if ( $this.css('position') == 'static' )
			$this.css('position', 'relative');
		
		$this
			.html('<div style="display:' + $this.css("display") + '; position: relative; z-index: 2;">' + this.innerHTML + '</div>')
			.prepend(html.join(''));
	});
};

})(jQuery);