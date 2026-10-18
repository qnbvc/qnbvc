(() => {
  const year = new Date().getFullYear();
  const footer = document.querySelector("footer");
  if (footer) {
    footer.dataset.year = String(year);
  }
})();
//# sourceMappingURL=/static/app.js.map
