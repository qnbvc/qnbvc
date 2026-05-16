class Player {
  constructor(id, x, y, paletteName, facing) {
    this.id = id;
    this.x = x;
    this.y = y;
    this.width = SPRITE_SIZE * SPRITE_SCALE;
    this.height = SPRITE_SIZE * SPRITE_SCALE;
    this.paletteName = paletteName;
    this.facing = facing;

    this.hp = 100;
    this.maxHp = 100;
    this.speed = 2.5;

    this.state = 'idle';
    this.prevState = 'idle';
    this.animFrame = 0;
    this.animTimer = 0;
    this.animSpeed = 8;

    this.attackCooldown = 0;
    this.attackCooldownMax = 20;
    this.attackDuration = 0;
    this.attackDurationMax = 10;
    this.attackRange = 50;

    this.defending = false;
    this.defenseCooldown = 0;
    this.defenseCooldownMax = 30;

    this.hitStun = 0;
    this.hitStunMax = 12;

    this.defeated = false;
    this.defeatTimer = 0;

    this.vx = 0;
    this.vy = 0;

    this.justLandedHit = false;
    this.hitX = 0;
    this.hitY = 0;
  }

  get centerX() {
    return this.x + this.width / 2;
  }

  get centerY() {
    return this.y + this.height / 2;
  }

  getAttackBox() {
    const range = this.attackRange;
    const w = 40;
    const h = 30;
    if (this.facing === 'right') {
      return {
        x: this.x + this.width,
        y: this.y + (this.height - h) / 2,
        width: w,
        height: h,
      };
    } else {
      return {
        x: this.x - w,
        y: this.y + (this.height - h) / 2,
        width: w,
        height: h,
      };
    }
  }

  getHitBox() {
    return {
      x: this.x + 6,
      y: this.y + 4,
      width: this.width - 12,
      height: this.height - 8,
    };
  }

  takeDamage(amount) {
    if (this.defeated) return;
    this.hp = Math.max(0, this.hp - amount);
    this.hitStun = this.hitStunMax;
    this.state = 'hit';
    if (this.hp <= 0) {
      this.state = 'defeated';
      this.defeated = true;
      this.defeatTimer = 60;
    }
  }

  update(input, opponent) {
    if (this.defeated) {
      this.defeatTimer--;
      this.animTimer++;
      if (this.animTimer >= this.animSpeed) {
        this.animTimer = 0;
        this.animFrame++;
      }
      return;
    }

    if (this.hitStun > 0) {
      this.hitStun--;
      this.animTimer++;
      if (this.animTimer >= this.animSpeed) {
        this.animTimer = 0;
        this.animFrame++;
      }
      if (this.hitStun <= 0 && this.state === 'hit') {
        this.state = 'idle';
      }
      return;
    }

    if (this.attackDuration > 0) {
      this.attackDuration--;
      this.animTimer++;
      if (this.animTimer >= this.animSpeed) {
        this.animTimer = 0;
        this.animFrame++;
      }
      if (this.attackDuration <= 0 && this.state === 'attacking') {
        this.state = 'idle';
      }
      return;
    }

    if (this.attackCooldown > 0) {
      this.attackCooldown--;
    }

    if (this.defenseCooldown > 0) {
      this.defenseCooldown--;
    }

    this.vx = 0;
    this.vy = 0;

    if (input.defend && this.defenseCooldown <= 0) {
      this.defending = true;
      this.state = 'defending';
    } else {
      if (this.defending) {
        this.defenseCooldown = this.defenseCooldownMax;
      }
      this.defending = false;
    }

    if (!this.defending) {
      if (input.up) this.vy = -this.speed;
      if (input.down) this.vy = this.speed;
      if (input.left) {
        this.vx = -this.speed;
        this.facing = 'left';
      }
      if (input.right) {
        this.vx = this.speed;
        this.facing = 'right';
      }
    } else {
      if (input.up) this.vy = -this.speed * 0.5;
      if (input.down) this.vy = this.speed * 0.5;
      if (input.left) {
        this.vx = -this.speed * 0.5;
        this.facing = 'left';
      }
      if (input.right) {
        this.vx = this.speed * 0.5;
        this.facing = 'right';
      }
    }

    if (input.attack && this.attackCooldown <= 0 && this.state !== 'attacking') {
      this.state = 'attacking';
      this.attackDuration = this.attackDurationMax;
      this.attackCooldown = this.attackCooldownMax;
      this.animFrame = 0;
      this.animTimer = 0;

      if (opponent && !opponent.defeated) {
        const atkBox = this.getAttackBox();
        const defBox = opponent.getHitBox();
        if (rectsOverlap(atkBox, defBox)) {
          const dmg = opponent.defending ? 3 : 10;
          opponent.takeDamage(dmg);
          this.justLandedHit = true;
          this.hitX = opponent.centerX;
          this.hitY = opponent.centerY;
        }
      }
    }

    if (this.state !== 'attacking' && this.state !== 'hit') {
      if (this.vx !== 0 || this.vy !== 0) {
        this.state = 'moving';
      } else if (!this.defending) {
        this.state = 'idle';
      }
    }

    this.x += this.vx;
    this.y += this.vy;

    this.x = Math.max(10, Math.min(800 - this.width - 10, this.x));
    this.y = Math.max(40, Math.min(600 - this.height - 10, this.y));

    this.animTimer++;
    if (this.animTimer >= this.animSpeed) {
      this.animTimer = 0;
      this.animFrame++;
    }
  }

  draw(ctx) {
    const frame = getSpriteFrame(this.paletteName, this.state, this.animFrame);
    if (!frame) return;

    if (this.state === 'hit' && this.hitStun > 0 && this.hitStun % 4 < 2) {
      ctx.globalAlpha = 0.6;
    }

    if (this.defending) {
      ctx.shadowColor = '#4488ff';
      ctx.shadowBlur = 12;
    }

    for (let row = 0; row < SPRITE_SIZE; row++) {
      for (let col = 0; col < SPRITE_SIZE; col++) {
        const color = frame[row][col];
        if (!color) continue;

        let drawCol = col;
        if (this.facing === 'left') {
          drawCol = SPRITE_SIZE - 1 - col;
        }

        ctx.fillStyle = color;
        ctx.fillRect(
          this.x + drawCol * SPRITE_SCALE,
          this.y + row * SPRITE_SCALE,
          SPRITE_SCALE,
          SPRITE_SCALE
        );
      }
    }

    ctx.shadowBlur = 0;
    ctx.globalAlpha = 1;
  }
}

function rectsOverlap(a, b) {
  return (
    a.x < b.x + b.width &&
    a.x + a.width > b.x &&
    a.y < b.y + b.height &&
    a.y + a.height > b.y
  );
}