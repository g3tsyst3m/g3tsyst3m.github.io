document.addEventListener('DOMContentLoaded', function () {
  const popupLinks = document.querySelectorAll('.popup-link');
  
  popupLinks.forEach(function (link) {
    link.addEventListener('click', function (event) {
      event.preventDefault();
      const popupUrl = link.getAttribute('href');
      window.open(popupUrl, 'popupWindow', 'width=600,height=400,scrollbars=yes');
    });
  });
});
