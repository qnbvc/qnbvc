class Game {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.input = new InputManager();
    this.renderer = new Renderer(this.ctx);
    this.hud = new HUD(this.ctx);

    this.state = 'MENU';
    this.winner = null;
    this.frameCount = 0;
    this.particles = [];
    this.shakeTimer = 0;
    this.shakeIntensity = 0;

    this.player1 = new Player(1, 150, 280, 'red', 'right');
    this.player2 = new Player(2, 600, 280, 'blue', 'left');

    this.lastTime = 0;
    this.accumulator = 0;
    this.timestep = 1000 / 60;
  }

  start() {
    this.state = 'PLAYING';
    this.winner = null;
    this.frameCount = 0;
    this.particles = [];
    this.player1 = new Player(1, 150, 280, 'red', 'right');
    this.player2 = new Player(2, 600, 280, 'blue', 'left');
  }

  reset() {
    this.start();
  }

  update() {
    this.frameCount++;

    if (this.state === 'MENU') {
      if (this.input.isSpacePressed()) {
        this.start();
      }
      this.input.clearJustPressed();
      return;
    }

    if (this.state === 'GAMEOVER') {
      if (this.input.isSpacePressed()) {
        this.reset();
      }
      this.input.clearJustPressed();
      this.updateParticles();
      return;
    }

    const p1Input = this.input.getPlayer1Input();
    const p2Input = this.input.getPlayer2Input();

    this.player1.update(p1Input, this.player2);
    this.player2.update(p2Input, this.player1);

    if (this.player1.justLandedHit) {
      this.addHitEffect(this.player1.hitX, this.player1.hitY);
      this.player1.justLandedHit = false;
    }
    if (this.player2.justLandedHit) {
      this.addHitEffect(this.player2.hitX, this.player2.hitY);
      this.player2.justLandedHit = false;
    }

    this.checkCollisions();
    this.updateParticles();

    if (this.player1.defeated) {
      this.state = 'GAMEOVER';
      this.winner = 2;
    } else if (this.player2.defeated) {
      this.state = 'GAMEOVER';
      this.winner = 1;
    }

    if (this.shakeTimer > 0) {
      this.shakeTimer--;
    }

    this.input.clearJustPressed();
  }

  checkCollisions() {
    const hb1 = this.player1.getHitBox();
    const hb2 = this.player2.getHitBox();
    if (rectsOverlap(hb1, hb2)) {
      const overlapX = Math.min(
        hb1.x + hb1.width - hb2.x,
        hb2.x + hb2.width - hb1.x
      );
      const overlapY = Math.min(
        hb1.y + hb1.height - hb2.y,
        hb2.y + hb2.height - hb1.y
      );
      if (overlapX < overlapY) {
        if (this.player1.centerX < this.player2.centerX) {
          this.player1.x -= overlapX / 2;
          this.player2.x += overlapX / 2;
        } else {
          this.player1.x += overlapX / 2;
          this.player2.x -= overlapX / 2;
        }
      } else {
        if (this.player1.centerY < this.player2.centerY) {
          this.player1.y -= overlapY / 2;
          this.player2.y += overlapY / 2;
        } else {
          this.player1.y += overlapY / 2;
          this.player2.y -= overlapY / 2;
        }
      }
    }
  }

  addHitEffect(x, y) {
    for (let i = 0; i < 8; i++) {
      this.particles.push({
        x,
        y,
        vx: (Math.random() - 0.5) * 6,
        vy: (Math.random() - 0.5) * 6,
        life: 20 + Math.random() * 15,
        maxLife: 35,
        size: 2 + Math.random() * 3,
        color: Math.random() > 0.5 ? '#ffffff' : '#ffd700',
      });
    }
    this.shakeTimer = 6;
    this.shakeIntensity = 4;
  }

  updateParticles() {
    for (let i = this.particles.length - 1; i >= 0; i--) {
      const p = this.particles[i];
      p.x += p.vx;
      p.y += p.vy;
      p.vy += 0.15;
      p.life--;
      if (p.life <= 0) {
        this.particles.splice(i, 1);
      }
    }
  }

  render() {
    const ctx = this.ctx;

    ctx.save();

    if (this.shakeTimer > 0) {
      const sx = (Math.random() - 0.5) * this.shakeIntensity;
      const sy = (Math.random() - 0.5) * this.shakeIntensity;
      ctx.translate(sx, sy);
    }

    this.renderer.drawBackground(this.frameCount);
    this.renderer.drawScene();

    this.player1.draw(ctx);
    this.player2.draw(ctx);

    this.renderer.drawAttackEffect(this.player1);
    this.renderer.drawAttackEffect(this.player2);

    this.renderer.drawParticles(this.particles);

    ctx.restore();

    this.hud.drawHealthBars(this.player1, this.player2);
    this.hud.drawPlayerNames(this.player1, this.player2);

    if (this.state === 'MENU') {
      this.hud.drawMenuScreen();
    } else if (this.state === 'GAMEOVER') {
      this.hud.drawGameOverScreen(this.winner);
    }
  }

  gameLoop(timestamp) {
    const deltaTime = timestamp - this.lastTime;
    this.lastTime = timestamp;

    this.accumulator += deltaTime;
    while (this.accumulator >= this.timestep) {
      this.update();
      this.accumulator -= this.timestep;
    }

    this.render();
    requestAnimationFrame((t) => this.gameLoop(t));
  }
}