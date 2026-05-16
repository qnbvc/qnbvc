class Renderer {
  constructor(ctx) {
    this.ctx = ctx;
    this.stars = [];
    for (let i = 0; i < 50; i++) {
      this.stars.push({
        x: Math.random() * 800,
        y: Math.random() * 200,
        size: 1 + Math.random() * 2,
        brightness: 0.3 + Math.random() * 0.7,
        twinkleSpeed: 0.02 + Math.random() * 0.04,
      });
    }
  }

  drawBackground(frameCount) {
    const ctx = this.ctx;

    const skyGrad = ctx.createLinearGradient(0, 0, 0, 300);
    skyGrad.addColorStop(0, '#0a0a2e');
    skyGrad.addColorStop(0.5, '#14144a');
    skyGrad.addColorStop(1, '#1a1a3e');
    ctx.fillStyle = skyGrad;
    ctx.fillRect(0, 0, 800, 300);

    for (const star of this.stars) {
      const alpha = star.brightness * (0.6 + 0.4 * Math.sin(frameCount * star.twinkleSpeed));
      ctx.fillStyle = `rgba(255, 255, 255, ${alpha})`;
      ctx.fillRect(star.x, star.y, star.size, star.size);
    }

    const moonX = 680;
    const moonY = 50;
    ctx.fillStyle = '#c8c8d0';
    ctx.beginPath();
    ctx.arc(moonX, moonY, 20, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = '#0a0a2e';
    ctx.beginPath();
    ctx.arc(moonX + 6, moonY - 3, 17, 0, Math.PI * 2);
    ctx.fill();

    const cityGrad = ctx.createLinearGradient(0, 200, 0, 300);
    cityGrad.addColorStop(0, 'rgba(20, 20, 40, 0)');
    cityGrad.addColorStop(1, 'rgba(20, 20, 40, 0.6)');
    ctx.fillStyle = cityGrad;
    ctx.fillRect(0, 200, 800, 100);

    const buildings = [
      { x: 30, w: 40, h: 60 },
      { x: 80, w: 30, h: 40 },
      { x: 120, w: 50, h: 80 },
      { x: 180, w: 35, h: 50 },
      { x: 220, w: 45, h: 70 },
      { x: 280, w: 30, h: 45 },
      { x: 320, w: 55, h: 90 },
      { x: 390, w: 40, h: 55 },
      { x: 440, w: 50, h: 75 },
      { x: 500, w: 35, h: 50 },
      { x: 550, w: 45, h: 65 },
      { x: 610, w: 30, h: 40 },
      { x: 650, w: 50, h: 85 },
      { x: 710, w: 40, h: 55 },
      { x: 760, w: 35, h: 45 },
    ];

    for (const b of buildings) {
      ctx.fillStyle = '#1a1a30';
      ctx.fillRect(b.x, 300 - b.h, b.w, b.h);

      for (let wy = 300 - b.h + 8; wy < 295; wy += 12) {
        for (let wx = b.x + 6; wx < b.x + b.w - 4; wx += 10) {
          if (Math.random() > 0.3) {
            ctx.fillStyle = `rgba(255, 200, 100, ${0.2 + Math.random() * 0.3})`;
            ctx.fillRect(wx, wy, 4, 5);
          }
        }
      }
    }
  }

  drawScene() {
    const ctx = this.ctx;

    const groundGrad = ctx.createLinearGradient(0, 300, 0, 600);
    groundGrad.addColorStop(0, '#1a3a2a');
    groundGrad.addColorStop(0.3, '#1e4a32');
    groundGrad.addColorStop(0.6, '#1a3a2a');
    groundGrad.addColorStop(1, '#162e22');
    ctx.fillStyle = groundGrad;
    ctx.fillRect(0, 300, 800, 300);

    ctx.strokeStyle = '#2a5a3a';
    ctx.lineWidth = 1;
    for (let y = 300; y < 600; y += 24) {
      ctx.beginPath();
      ctx.moveTo(0, y + 0.5);
      ctx.lineTo(800, y + 0.5);
      ctx.stroke();
    }
    for (let x = 0; x < 800; x += 24) {
      ctx.beginPath();
      ctx.moveTo(x + 0.5, 300);
      ctx.lineTo(x + 0.5, 600);
      ctx.stroke();
    }

    ctx.fillStyle = '#2a5a3a';
    ctx.fillRect(0, 300, 800, 2);

    ctx.strokeStyle = '#3a3a5e';
    ctx.lineWidth = 4;
    ctx.strokeRect(2, 2, 796, 596);

    ctx.strokeStyle = '#2a2a4e';
    ctx.lineWidth = 2;
    ctx.strokeRect(6, 6, 788, 588);

    ctx.fillStyle = '#2a2a4e44';
    ctx.fillRect(0, 0, 800, 8);
    ctx.fillRect(0, 592, 800, 8);
    ctx.fillRect(0, 0, 8, 600);
    ctx.fillRect(792, 0, 8, 600);
  }

  drawParticles(particles) {
    const ctx = this.ctx;
    for (const p of particles) {
      const alpha = p.life / p.maxLife;
      ctx.globalAlpha = alpha;
      ctx.fillStyle = p.color;
      ctx.fillRect(p.x - p.size / 2, p.y - p.size / 2, p.size, p.size);
    }
    ctx.globalAlpha = 1;
  }

  drawAttackEffect(player) {
    if (player.state !== 'attacking') return;
    const ctx = this.ctx;
    const progress = 1 - (player.attackDuration / player.attackDurationMax);
    const len = 30 * progress;
    const cx = player.centerX;
    const cy = player.centerY;
    const dir = player.facing === 'right' ? 1 : -1;

    ctx.save();
    ctx.globalAlpha = 0.8 * (1 - progress * 0.5);

    const grad = ctx.createLinearGradient(
      cx, cy,
      cx + dir * len, cy
    );
    grad.addColorStop(0, 'rgba(255, 255, 255, 0.9)');
    grad.addColorStop(0.5, 'rgba(255, 200, 50, 0.6)');
    grad.addColorStop(1, 'rgba(255, 200, 50, 0)');

    ctx.fillStyle = grad;
    ctx.fillRect(
      Math.min(cx, cx + dir * len),
      cy - 6,
      Math.abs(dir * len),
      12
    );

    ctx.restore();
  }
}