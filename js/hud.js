class HUD {
  constructor(ctx) {
    this.ctx = ctx;
    this.menuBlink = 0;
  }

  drawHealthBars(p1, p2) {
    const ctx = this.ctx;
    const barWidth = 250;
    const barHeight = 18;
    const barY = 14;

    const p1BarX = 20;
    const p2BarX = 800 - 20 - barWidth;

    this.drawSingleBar(ctx, p1BarX, barY, barWidth, barHeight, p1, '#e63946', '#5c0000');
    this.drawSingleBar(ctx, p2BarX, barY, barWidth, barHeight, p2, '#457b9d', '#0a2472');

    ctx.fillStyle = '#ffffff';
    ctx.font = '10px "Press Start 2P", monospace';
    ctx.textAlign = 'center';

    const p1HpText = `${Math.ceil(p1.hp)}`;
    ctx.fillStyle = p1.hp > 30 ? '#ffffff' : '#ff6b6b';
    ctx.fillText(p1HpText, p1BarX + barWidth / 2, barY + barHeight - 4);

    const p2HpText = `${Math.ceil(p2.hp)}`;
    ctx.fillStyle = p2.hp > 30 ? '#ffffff' : '#ff6b6b';
    ctx.fillText(p2HpText, p2BarX + barWidth / 2, barY + barHeight - 4);
  }

  drawSingleBar(ctx, x, y, w, h, player, fillColor, bgColor) {
    ctx.fillStyle = '#1a1a2e';
    ctx.fillRect(x - 1, y - 1, w + 2, h + 2);

    ctx.fillStyle = bgColor;
    ctx.fillRect(x, y, w, h);

    const hpRatio = player.hp / player.maxHp;
    const fillW = w * hpRatio;

    const grad = ctx.createLinearGradient(x, y, x, y + h);
    if (hpRatio > 0.5) {
      grad.addColorStop(0, fillColor);
      grad.addColorStop(1, '#8b0000');
    } else if (hpRatio > 0.25) {
      grad.addColorStop(0, '#ff8c00');
      grad.addColorStop(1, '#cc4400');
    } else {
      grad.addColorStop(0, '#ff4444');
      grad.addColorStop(1, '#880000');
    }
    ctx.fillStyle = grad;
    ctx.fillRect(x, y, fillW, h);

    ctx.strokeStyle = '#4444aa';
    ctx.lineWidth = 1;
    ctx.strokeRect(x, y, w, h);

    for (let px = x + 4; px < x + fillW - 4; px += 8) {
      ctx.fillStyle = 'rgba(255,255,255,0.08)';
      ctx.fillRect(px, y + 2, 3, h - 4);
    }
  }

  drawPlayerNames(p1, p2) {
    const ctx = this.ctx;

    ctx.font = '9px "Press Start 2P", monospace';
    ctx.textAlign = 'left';
    ctx.fillStyle = '#ff6b6b';
    ctx.fillText('P1', 20, 40);

    ctx.textAlign = 'right';
    ctx.fillStyle = '#64b5f6';
    ctx.fillText('P2', 780, 40);
  }

  drawMenuScreen() {
    const ctx = this.ctx;
    this.menuBlink++;

    ctx.fillStyle = 'rgba(0, 0, 0, 0.7)';
    ctx.fillRect(0, 0, 800, 600);

    ctx.textAlign = 'center';

    ctx.fillStyle = '#ffd700';
    ctx.font = '28px "Press Start 2P", monospace';
    ctx.fillText('机甲对战', 400, 160);

    ctx.fillStyle = '#ff6b6b';
    ctx.font = '12px "Press Start 2P", monospace';
    ctx.fillText('VS', 400, 210);

    ctx.fillStyle = '#64b5f6';
    ctx.font = '10px "Press Start 2P", monospace';
    ctx.fillText('本地双人  ·  像素格斗', 400, 250);

    ctx.fillStyle = '#8888aa';
    ctx.font = '8px "Press Start 2P", monospace';
    ctx.fillText('玩家1: W/A/S/D 移动  F 攻击  G 防御', 400, 310);
    ctx.fillText('玩家2: 方向键 移动  J 攻击  K 防御', 400, 335);

    ctx.fillStyle = '#ffffff';
    ctx.font = '10px "Press Start 2P", monospace';

    if (Math.floor(this.menuBlink / 20) % 2 === 0) {
      ctx.fillStyle = '#ffd700';
      ctx.fillText('按 空格键 开始', 400, 400);
    }

    ctx.fillStyle = '#666688';
    ctx.font = '7px "Press Start 2P", monospace';
    ctx.fillText('击败对手 · 守护你的机甲', 400, 450);
  }

  drawGameOverScreen(winner) {
    const ctx = this.ctx;

    ctx.fillStyle = 'rgba(0, 0, 0, 0.6)';
    ctx.fillRect(0, 0, 800, 600);

    ctx.textAlign = 'center';

    if (winner === 1) {
      ctx.fillStyle = '#ff6b6b';
      ctx.font = '22px "Press Start 2P", monospace';
      ctx.fillText('玩家1 胜利!', 400, 240);
    } else {
      ctx.fillStyle = '#64b5f6';
      ctx.font = '22px "Press Start 2P", monospace';
      ctx.fillText('玩家2 胜利!', 400, 240);
    }

    ctx.fillStyle = '#ffd700';
    ctx.font = '14px "Press Start 2P", monospace';
    ctx.fillText('K.O.!', 400, 290);

    ctx.fillStyle = '#8888aa';
    ctx.font = '9px "Press Start 2P", monospace';

    if (Math.floor(Date.now() / 400) % 2 === 0) {
      ctx.fillStyle = '#ffffff';
      ctx.font = '10px "Press Start 2P", monospace';
      ctx.fillText('按 空格键 重新开始', 400, 360);
    }
  }
}