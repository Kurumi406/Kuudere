$(document).ready(function () {
	$("#m-menu").click(function (e) {
		$("#menu, #m-menu").toggleClass("active");
	});
	$('a[href*="#"]').on('click', function (e) {
		e.preventDefault();

		$('html, body').animate({
			scrollTop: $($(this).attr('href')).offset().top
		}, 500, 'linear');
	});
});
