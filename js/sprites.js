const SPRITE_SIZE = 16;
const SPRITE_SCALE = 3;

const PALETTES = {
  red: {
    name: 'red',
    colors: [
      null,
      '#5c0000',
      '#e63946',
      '#ff8c8c',
      '#6b6b6b',
      '#ffffff',
      '#ffd700',
      '#8b0000',
    ],
  },
  blue: {
    name: 'blue',
    colors: [
      null,
      '#0a2472',
      '#457b9d',
      '#a8dadc',
      '#6b6b6b',
      '#ffffff',
      '#ffd700',
      '#1d3557',
    ],
  },
};

function applyPalette(data, colors) {
  return data.map(row =>
    row.map(idx => (idx === 0 ? null : colors[idx]))
  );
}

const BASE_SPRITE = [
  [0,0,0,0,0,1,1,1,1,1,1,0,0,0,0,0],
  [0,0,0,0,1,1,1,1,1,1,1,1,0,0,0,0],
  [0,0,0,1,1,2,2,2,2,2,2,1,1,0,0,0],
  [0,0,0,1,2,5,5,2,2,5,5,2,1,0,0,0],
  [0,0,0,1,1,2,2,2,2,2,2,1,1,0,0,0],
  [0,0,0,0,1,4,2,2,2,2,4,1,0,0,0,0],
  [0,0,0,1,1,2,2,2,2,2,2,1,1,0,0,0],
  [0,0,1,1,2,2,6,2,2,6,2,2,1,1,0,0],
  [0,0,1,2,2,2,2,2,2,2,2,2,2,1,0,0],
  [0,0,1,1,2,2,2,2,2,2,2,2,1,1,0,0],
  [0,0,0,1,1,4,2,2,2,2,4,1,1,0,0,0],
  [0,0,0,0,1,2,2,4,4,2,2,1,0,0,0,0],
  [0,0,0,0,1,2,2,4,4,2,2,1,0,0,0,0],
  [0,0,0,0,0,1,2,2,2,2,1,0,0,0,0,0],
  [0,0,0,0,0,1,2,2,2,2,1,0,0,0,0,0],
  [0,0,0,0,0,0,1,1,1,1,0,0,0,0,0,0],
];

function makeWalk1(base) {
  const s = base.map(row => [...row]);
  s[12] = [0,0,0,0,0,1,2,4,4,2,1,0,0,0,0,0];
  s[13] = [0,0,0,0,0,0,2,2,2,2,0,0,0,0,0,0];
  s[14] = [0,0,0,0,0,1,2,2,2,2,1,0,0,0,0,0];
  s[15] = [0,0,0,0,0,0,1,1,1,1,0,0,0,0,0,0];
  return s;
}

function makeWalk2(base) {
  const s = base.map(row => [...row]);
  s[12] = [0,0,0,0,1,2,2,4,4,2,2,1,0,0,0,0];
  s[13] = [0,0,0,0,0,1,2,2,2,2,1,0,0,0,0,0];
  s[14] = [0,0,0,0,0,0,2,2,2,2,0,0,0,0,0,0];
  s[15] = [0,0,0,0,0,1,1,1,1,1,1,0,0,0,0,0];
  return s;
}

function makeAttack(base) {
  const s = base.map(row => [...row]);
  for (let r = 6; r <= 9; r++) {
    s[r][15] = s[r][14] > 0 ? 3 : 0;
  }
  s[7][15] = 5;
  s[7][14] = 5;
  s[8][15] = 3;
  s[8][14] = 3;
  return s;
}

function makeDefend(base) {
  const s = base.map(row => [...row]);
  for (let r = 3; r <= 10; r++) {
    if (s[r][1] === 0 && r >= 4 && r <= 9) {
      s[r][1] = 4;
      s[r][2] = 4;
    }
  }
  s[4][1] = 4;
  s[4][2] = 4;
  s[5][1] = 4;
  s[5][2] = 4;
  s[8][1] = 4;
  s[8][2] = 4;
  s[9][1] = 4;
  s[9][2] = 4;
  return s;
}

function makeHit(base) {
  const s = base.map(row => [...row]);
  for (let r = 0; r < 16; r++) {
    for (let c = 0; c < 15; c++) {
      s[r][c] = s[r][c + 1];
    }
    s[r][15] = 0;
  }
  for (let r = 3; r <= 5; r++) {
    s[r][0] = 0;
  }
  return s;
}

function createMechaSprite(palette) {
  const p = palette.colors;
  const base = applyPalette(BASE_SPRITE, p);
  return {
    base,
    walk1: applyPalette(makeWalk1(BASE_SPRITE), p),
    walk2: applyPalette(makeWalk2(BASE_SPRITE), p),
    attack: applyPalette(makeAttack(BASE_SPRITE), p),
    defend: applyPalette(makeDefend(BASE_SPRITE), p),
    hit: applyPalette(makeHit(BASE_SPRITE), p),
  };
}

const SPRITES = {
  red: createMechaSprite(PALETTES.red),
  blue: createMechaSprite(PALETTES.blue),
};

function getSpriteFrame(paletteName, state, frameIndex) {
  const spriteSet = SPRITES[paletteName];
  if (!spriteSet) return null;

  switch (state) {
    case 'idle':
      return spriteSet.base;
    case 'moving':
      return frameIndex % 2 === 0 ? spriteSet.walk1 : spriteSet.walk2;
    case 'attacking':
      return spriteSet.attack;
    case 'defending':
      return spriteSet.defend;
    case 'hit':
      return spriteSet.hit;
    case 'defeated':
      return spriteSet.hit;
    default:
      return spriteSet.base;
  }
}