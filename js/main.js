(function () {
  const canvas = document.getElementById('gameCanvas');
  if (!canvas) {
    console.error('Canvas element not found!');
    return;
  }

  const ctx = canvas.getContext('2d');
  ctx.imageSmoothingEnabled = false;

  const game = new Game(canvas);

  requestAnimationFrame((t) => game.gameLoop(t));
})();