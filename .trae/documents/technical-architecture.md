## 1. 架构设计

```mermaid
flowchart TD
    "表现层" --> "游戏引擎层"
    "游戏引擎层" --> "数据层"
    "表现层" --> "Canvas渲染"
    "表现层" --> "HUD界面"
    "游戏引擎层" --> "物理引擎"
    "游戏引擎层" --> "战斗系统"
    "游戏引擎层" --> "动画系统"
    "游戏引擎层" --> "输入管理"
    "数据层" --> "游戏状态"
    "数据层" --> "角色数据"
    "数据层" --> "动画帧数据"
```

## 2. 技术选型

- **前端**：原生 HTML5 + CSS3 + JavaScript (Canvas API)
- **渲染方式**：Canvas 2D Context，像素级绘制
- **初始化工具**：纯静态 HTML 文件，无需构建工具
- **后端**：无（纯前端本地双人游戏）
- **数据库**：无（所有数据在内存中）

## 3. 代码结构

```
/workspace/
├── index.html          # 主页面，引入所有资源
├── css/
│   └── style.css       # 页面样式，像素风格主题
├── js/
│   ├── main.js         # 入口文件，游戏循环初始化
│   ├── game.js         # 游戏主逻辑，状态管理
│   ├── player.js       # 玩家类，角色属性和行为
│   ├── input.js        # 键盘输入管理
│   ├── renderer.js     # Canvas渲染器，绘制所有元素
│   ├── sprites.js      # 像素精灵数据，角色帧动画定义
│   └── hud.js          # HUD界面绘制（血条、文字）
```

## 4. 核心模块设计

### 4.1 游戏主循环 (game.js)
- 使用 requestAnimationFrame 驱动
- 状态管理：MENU → PLAYING → GAMEOVER
- 每帧更新：输入处理 → 物理更新 → 碰撞检测 → 战斗判定 → 渲染

### 4.2 玩家模块 (player.js)
- 属性：x, y, width, height, hp, maxHp, speed, state, direction, facing
- 状态机：idle, moving, attacking, defending, hit, defeated
- 方法：move(), attack(), defend(), takeDamage(), update()

### 4.3 输入管理 (input.js)
- 监听 keydown/keyup 事件
- 玩家1: W/A/S/D + F(攻击) + G(防御)
- 玩家2: 方向键 + J(攻击) + K(防御)
- 防止按键冲突和幽灵按键

### 4.4 渲染器 (renderer.js)
- 绘制背景场景（地面、天空、装饰）
- 绘制像素机甲角色（基于精灵数据）
- 绘制攻击特效
- 像素风格缩放渲染

### 4.5 精灵系统 (sprites.js)
- 使用二维数组定义像素颜色矩阵
- 定义机甲不同状态下的帧动画数据
- 包含：站立帧、行走帧、攻击帧、防御帧、受击帧
- 颜色映射表（像素调色板）

### 4.6 HUD系统 (hud.js)
- 绘制双方血条（像素风格块状）
- 绘制操作提示文字
- 绘制游戏状态文字（开始/胜利/失败）

## 5. 数据模型

### 5.1 游戏状态
```
GameState {
  status: 'MENU' | 'PLAYING' | 'GAMEOVER'
  winner: null | 1 | 2
  frameCount: number
}
```

### 5.2 玩家数据
```
Player {
  id: 1 | 2
  x: number
  y: number
  width: 16
  height: 16
  hp: 100
  maxHp: 100
  speed: 3
  state: 'idle' | 'moving' | 'attacking' | 'defending' | 'hit' | 'defeated'
  direction: 'right' | 'left'
  attackCooldown: 0
  defenseCooldown: 0
  animFrame: 0
  animTimer: 0
}
```

### 5.3 碰撞箱
- 机甲碰撞箱：16x16像素
- 攻击判定箱：从机甲位置向前延伸约40px
- 场景边界：画布四周

## 6. 战斗系统逻辑

### 6.1 攻击判定流程
1. 玩家按下攻击键 → 进入 attacking 状态
2. 检查攻击冷却是否结束
3. 生成攻击判定矩形（朝向前方延伸）
4. 检测是否与对方碰撞箱重叠
5. 若命中：
   - 若对方在防御状态 → 造成 3 点伤害
   - 若对方非防御状态 → 造成 10 点伤害
   - 对方进入 hit 状态（短暂僵直）
6. 进入攻击冷却

### 6.2 防御逻辑
1. 玩家按住防御键 → 进入 defending 状态
2. 移动速度降低50%
3. 被攻击时伤害减少70%
4. 防御有1秒冷却（松开后开始计算）

## 7. 素材方案

### 7.1 像素精灵设计
- 使用代码内定义的颜色矩阵（无需外部图片资源）
- 每个角色16x16像素网格
- 使用调色板索引方式定义像素颜色

### 7.2 场景设计
- 地面：绿色像素网格纹理
- 背景：深色星空/城市剪影
- 边界：像素风格围墙

### 7.3 特效设计
- 攻击命中：白色闪光效果
- 防御：蓝色护盾闪烁
- 行走：地面尘土粒子