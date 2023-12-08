let swiperCards = new Swiper(".card__content", {
    loop: true,
    spaceBetween: 32,
    grabCursor: true,

    pagination: {
       el: ".swiper-pagination",
       clickable: true,
       dynamicBullets: true,
    },

    navigation: {
       nextEl: ".swiper-button-next",
       prevEl: ".swiper-button-prev",
    },

    breakpoints:{
       600: {
          slidesPerView: 2,
       },
       968: {
          slidesPerView: 3,
       },
    },
 });
//var videoIds = ['gyXcu78bWis', '61WuIZIG5N0', 'yjxnvcZ7dlc','' /* добавьте идентификаторы для других видео */];

//function onYouTubeIframeAPIReady() {
//for (var i = 0; i < videoIds.length; i++) {
//createVideoPlayer('video-' + (i + 1), videoIds[i]);
//}
//}

//function createVideoPlayer(containerId, videoId) {
//var container = document.getElementById(containerId);

// Замените настройки размера и другие параметры, если необходимо
//var player = new YT.Player(container, {
//height: '315',
//width: '560',
//videoId: videoId,
//});
//}