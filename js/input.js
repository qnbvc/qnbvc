class InputManager {
  constructor() {
    this.keys = {};
    this.justPressed = {};

    this.onKeyDown = (e) => {
      if (!this.keys[e.code]) {
        this.justPressed[e.code] = true;
      }
      this.keys[e.code] = true;
      if (['Space', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(e.code)) {
        e.preventDefault();
      }
    };

    this.onKeyUp = (e) => {
      this.keys[e.code] = false;
    };

    window.addEventListener('keydown', this.onKeyDown);
    window.addEventListener('keyup', this.onKeyUp);
  }

  isDown(code) {
    return !!this.keys[code];
  }

  wasPressed(code) {
    return !!this.justPressed[code];
  }

  clearJustPressed() {
    this.justPressed = {};
  }

  getPlayer1Input() {
    return {
      up: this.isDown('KeyW'),
      down: this.isDown('KeyS'),
      left: this.isDown('KeyA'),
      right: this.isDown('KeyD'),
      attack: this.wasPressed('KeyF'),
      defend: this.isDown('KeyG'),
    };
  }

  getPlayer2Input() {
    return {
      up: this.isDown('ArrowUp'),
      down: this.isDown('ArrowDown'),
      left: this.isDown('ArrowLeft'),
      right: this.isDown('ArrowRight'),
      attack: this.wasPressed('KeyJ'),
      defend: this.isDown('KeyK'),
    };
  }

  isSpacePressed() {
    return this.wasPressed('Space');
  }
}