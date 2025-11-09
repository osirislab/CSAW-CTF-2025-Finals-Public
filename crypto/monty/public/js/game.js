const canvas = document.getElementById('gameCanvas');
const ctx = canvas.getContext('2d');
const hostSpeech = document.getElementById('hostSpeech');
const answerInput = document.getElementById('answerInput');
const answerField = document.getElementById('answerField');
const submitBtn = document.getElementById('submitBtn');

const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const ws = new WebSocket(`${protocol}//${window.location.host}`);

const audioCtx = new (window.AudioContext || window.webkitAudioContext)();

let gameState = {
    player: { x: 300, y: 380 },
    keys: {},
    phase: 'initial',
    wins: 0,
    losses: 0,
    switches: 0,
    stays: 0,
    selectedDoor: null,
    revealedDoor: null,
    prizeDoor: null,
    showPuzzle: false,
    puzzleData: null,
    audienceReaction: null,
    reactionTime: 0,
    morseVisual: false
};

const doors = [
    {x: 100, y: 200, label: 'DOOR 1'},
    {x: 320, y: 200, label: 'DOOR 2'},
    {x: 540, y: 200, label: 'DOOR 3'}
];

const host = {x: 320, y: 100};

// Spread audience members more and move them higher
const audience = [];
for (let row = 0; row < 4; row++) {
    for (let i = 0; i < 20; i++) {
        audience.push({
            x: 20 + i * 30,
            y: 390 + row * 18,
            bobOffset: Math.random() * Math.PI * 2,
            waveSpeed: 2 + Math.random() * 2
        });
    }
}

ws.onopen = () => {
    hostSpeech.textContent = "Welcome to THE MONTY HALL SHOW! I'm your host, Monty! Walk to a door and press SPACE to begin!";
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    if (data.type === 'init' || data.type === 'update') {
        updateGameState(data.state);
        if (data.prizeDoor !== undefined) {
            gameState.prizeDoor = data.prizeDoor;
        }
        if (data.message) {
            handleMessage(data.message, data);
        }
    } else if (data.type === 'playMorse') {
        gameState.morseVisual = true;
        playMorseCode(data.events);
        if (data.message) {
            handleMessage(data.message, data);
        }
        const morseEndTime = data.events[data.events.length - 1].time + 1000;
        setTimeout(() => {
            gameState.morseVisual = false;
        }, morseEndTime);
    } else if (data.type === 'showPuzzle') {
        gameState.showPuzzle = true;
        gameState.puzzleData = data.puzzle;
        if (data.message) {
            handleMessage(data.message, data);
        }
        renderPuzzle();
    }
};

function updateGameState(state) {
    gameState = { ...gameState, ...state };
    document.getElementById('winCount').textContent = state.wins;
    document.getElementById('lossCount').textContent = state.losses;
    document.getElementById('switchCount').textContent = state.switches;
    document.getElementById('stayCount').textContent = state.stays;
}

function setAudienceReaction(reaction) {
    gameState.audienceReaction = reaction;
    gameState.reactionTime = Date.now();
}

function handleMessage(message, data) {
    switch(message) {
        case 'firstSelected':
            hostSpeech.textContent = "Interesting choice! But before we open it... Let me show you what's behind another door...";
            gameState.audienceReaction = null;
            break;
        case 'doorRevealed':
            hostSpeech.textContent = "Now, here's the big question: Do you want to STAY with your choice, or SWITCH to the other door?";
            gameState.audienceReaction = null;
            break;
        case 'roundWon':
            hostSpeech.textContent = `🎉 YOU WIN! 🎉 Excellent! Keep going...`;
            setAudienceReaction('cheer');
            setTimeout(() => gameState.audienceReaction = null, 4000);
            break;
        case 'roundLost':
            hostSpeech.textContent = "Oh no! The prize was behind Door #" + (data.prizeDoor + 1);
            setAudienceReaction('boo');
            setTimeout(() => gameState.audienceReaction = null, 4000);
            break;
        case 'askQuestion':
            hostSpeech.textContent = "🎉🎉 CONGRATULATIONS! 🎉 You've won 3 rounds! But before I give you the grand prize... You must answer THE ULTIMATE QUESTION!";
            answerInput.classList.add('visible');
            setAudienceReaction('cheer');
            setTimeout(() => {
                gameState.audienceReaction = null;
                answerField.focus();
            }, 4000);
            break;
        case 'correctAnswer':
            answerInput.classList.remove('visible');
            hostSpeech.textContent = "That is right! I just wish I knew what was next, if only I had 30 extra lives...";
            setAudienceReaction('cheer');
            setTimeout(() => gameState.audienceReaction = null, 4000);
            break;
        case 'wrongAnswer':
            hostSpeech.textContent = "Incorrect! Think deeper... what is the answer to life, the universe, and everything?";
            setAudienceReaction('boo');
            setTimeout(() => gameState.audienceReaction = null, 3000);
            break;
        case 'stayedOnce':
            hostSpeech.textContent = "You chose to STAY! You'll never win the grand prize unless you learn to play the game! Game over.";
            setAudienceReaction('boo');
            break;
        case 'codeAccepted':
            hostSpeech.textContent = "🎉 KONAMI CODE ACCEPTED! 🎉";
            setAudienceReaction('cheer');
            setTimeout(() => gameState.audienceReaction = null, 3000);
            break;
        case 'morseComplete':
            hostSpeech.textContent = "The transmission has ended. Walk to me and press SPACE to continue...";
            break;
        case 'showPuzzle':
            hostSpeech.textContent = "Now for the final test...";
            break;
        case 'puzzleCorrect':
            gameState.showPuzzle = false;
            displayHint();
            break;
        case 'puzzleWrong':
            gameState.showPuzzle = false;
            hostSpeech.textContent = "Wrong! You have failed the final test. Game over.";
            setAudienceReaction('boo');
            break;
        case 'newRound':
            gameState.prizeDoor = null;
            hostSpeech.textContent = "Ready for another round? Walk to a door and press SPACE!";
            gameState.audienceReaction = null;
            break;
    }
}

function displayHint() {
    const hintDiv = document.createElement('div');
    hintDiv.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#000;border:3px solid #666;padding:40px;max-width:500px;color:#888;font-family:"Courier New",monospace;z-index:2000;line-height:1.8;box-shadow:0 0 50px rgba(0,0,0,0.9);';
    hintDiv.innerHTML = `<div style="color:#aaa;font-size:16px;margin-bottom:20px;text-align:center;">The transmission was encoded using a cipher shift based on how you played the game show. shift = (wins × 3 + losses × 7 + switches × 5 + stays × 11) % 26 </div><button id="closeHint" style="background:#333;color:#666;border:2px solid #666;padding:10px 20px;margin-top:20px;font-family:inherit;cursor:pointer;width:100%;">CLOSE</button>`;
    document.body.appendChild(hintDiv);
    
    document.getElementById('closeHint').onclick = () => {
        document.body.removeChild(hintDiv);
        hostSpeech.textContent = "Decode the transmission to find the flag!";
    };
}

function renderPuzzle() {
    const puzzleDiv = document.createElement('div');
    puzzleDiv.id = 'puzzleOverlay';
    puzzleDiv.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.95);display:flex;align-items:center;justify-content:center;z-index:1000;';
    
    const puzzleBox = document.createElement('div');
    puzzleBox.style.cssText = 'background:#0a0a0a;border:3px solid #444;padding:30px;max-width:700px;color:#888;font-family:"Courier New",monospace;box-shadow:0 0 30px rgba(0,0,0,0.8);';
    
    const title = document.createElement('div');
    title.style.cssText = 'color:#666;font-size:22px;margin-bottom:20px;text-align:center;';
    title.textContent = '★ THE FINAL RIDDLE ★';
    puzzleBox.appendChild(title);
    
    const question = document.createElement('div');
    question.style.cssText = 'color:#aaa;font-size:15px;margin-bottom:25px;line-height:1.8;white-space:pre-wrap;';
    question.textContent = gameState.puzzleData.question;
    puzzleBox.appendChild(question);
    
    gameState.puzzleData.options.forEach((opt, idx) => {
        const btn = document.createElement('button');
        btn.style.cssText = 'display:block;width:100%;background:#222;color:#888;border:2px solid #444;padding:15px;margin:10px 0;font-family:"Courier New",monospace;font-size:13px;cursor:pointer;text-align:left;line-height:1.5;';
        btn.textContent = `${String.fromCharCode(65 + idx)}. ${opt}`;
        btn.onmouseover = () => {
            btn.style.background = '#333';
            btn.style.borderColor = '#666';
            btn.style.color = '#aaa';
        };
        btn.onmouseout = () => {
            btn.style.background = '#222';
            btn.style.borderColor = '#444';
            btn.style.color = '#888';
        };
        btn.onclick = () => {
            document.body.removeChild(puzzleDiv);
            ws.send(JSON.stringify({
                action: 'puzzleAnswer',
                answer: idx
            }));
        };
        puzzleBox.appendChild(btn);
    });
    
    puzzleDiv.appendChild(puzzleBox);
    document.body.appendChild(puzzleDiv);
}

document.addEventListener('keydown', (e) => {
    gameState.keys[e.key.toLowerCase()] = true;
    
    if (gameState.phase === 'waitingForCode') {
        ws.send(JSON.stringify({
            action: 'konamiKey',
            keyCode: e.keyCode
        }));
    }
    
    if (e.key === ' ') {
        e.preventDefault();
        
        if (gameState.phase === 'walkToMonty') {
            const dist = Math.sqrt(Math.pow(gameState.player.x + 10 - host.x, 2) + Math.pow(gameState.player.y + 15 - host.y, 2));
            if (dist < 60) {
                ws.send(JSON.stringify({
                    action: 'talkToMonty'
                }));
            }
        } else {
            const nearDoor = getNearestDoor();
            if (nearDoor !== null && (gameState.phase === 'initial' || gameState.phase === 'finalChoice')) {
                ws.send(JSON.stringify({
                    action: 'selectDoor',
                    door: nearDoor
                }));
            }
        }
    }
});

document.addEventListener('keyup', (e) => {
    gameState.keys[e.key.toLowerCase()] = false;
});

submitBtn.addEventListener('click', () => {
    ws.send(JSON.stringify({
        action: 'submitAnswer',
        answer: answerField.value.trim()
    }));
    answerField.value = '';
});

answerField.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        submitBtn.click();
    }
});

function getNearestDoor() {
    const p = gameState.player;
    let nearest = null;
    let minDist = 80;

    doors.forEach((door, index) => {
        const dist = Math.abs(p.x + 10 - door.x);
        if (dist < minDist && p.y < 350) {
            minDist = dist;
            nearest = index;
        }
    });

    return nearest;
}

function movePlayer() {
    const p = gameState.player;
    const speed = 3;
    
    if (gameState.keys['arrowleft'] || gameState.keys['a']) {
        p.x = Math.max(10, p.x - speed);
    }
    if (gameState.keys['arrowright'] || gameState.keys['d']) {
        p.x = Math.min(610, p.x + speed);
    }
    if (gameState.keys['arrowup'] || gameState.keys['w']) {
        p.y = Math.max(10, p.y - speed);
    }
    if (gameState.keys['arrowdown'] || gameState.keys['s']) {
        p.y = Math.min(370, p.y + speed);
    }
}

function playMorseCode(events) {
    events.forEach(event => {
        const startTime = audioCtx.currentTime + event.time / 1000;
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        
        osc.frequency.value = 800;
        osc.type = 'sine';
        gain.gain.value = 0.2;
        
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        
        osc.start(startTime);
        osc.stop(startTime + event.duration / 1000);
    });
}

function drawBackground() {
    const gradient = ctx.createLinearGradient(0, 0, 0, canvas.height);
    gradient.addColorStop(0, '#1a0033');
    gradient.addColorStop(1, '#330066');
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    const spots = [100, 320, 540];
    spots.forEach(x => {
        const spotGrad = ctx.createRadialGradient(x, 200, 0, x, 200, 100);
        spotGrad.addColorStop(0, 'rgba(255, 255, 200, 0.3)');
        spotGrad.addColorStop(1, 'rgba(255, 255, 200, 0)');
        ctx.fillStyle = spotGrad;
        ctx.fillRect(x - 100, 100, 200, 200);
    });
    
    // Audience area - moved higher
    ctx.fillStyle = '#222';
    ctx.fillRect(0, 360, canvas.width, 120);
    
    for (let i = 0; i < canvas.width; i += 40) {
        ctx.fillStyle = i % 80 === 0 ? '#ff0' : '#f00';
        ctx.fillRect(i, 0, 20, 10);
    }
}

function drawMorseVisual() {
    if (gameState.morseVisual) {
        const time = Date.now() / 100;
        const pulse = Math.sin(time) * 0.5 + 0.5;
        
        ctx.fillStyle = '#ff0';
        ctx.font = 'bold 20px Courier New';
        ctx.textAlign = 'center';
        
        const textPulse = 0.7 + pulse * 0.3;
        ctx.shadowBlur = 15;
        ctx.shadowColor = `rgba(255, 255, 0, ${textPulse})`;
        ctx.fillText('♪♫ TRANSMISSION PLAYING ♪♫', 320, 58);
        ctx.shadowBlur = 0;
        
        ctx.font = 'bold 28px Courier New';
        const dots = ['•', '−', '•', '−', '•'];
        for (let i = 0; i < 5; i++) {
            const offset = Math.sin(time * 2 + i * 0.8) * 3;
            const dotPulse = 0.6 + Math.sin(time * 3 + i * 1.2) * 0.4;
            ctx.shadowBlur = 20;
            ctx.shadowColor = `rgba(255, 255, 0, ${dotPulse})`;
            ctx.fillText(dots[i], 220 + i * 50, 42 + offset);
        }
        ctx.shadowBlur = 0;
        
        ctx.textAlign = 'left';
    }
}

function drawAudience() {
    const time = Date.now() / 1000;
    const timeSinceReaction = gameState.reactionTime ? (Date.now() - gameState.reactionTime) / 1000 : 999;
    
    audience.forEach((person, idx) => {
        const bobAmount = Math.sin(time * person.waveSpeed + person.bobOffset) * 1.5;
        const y = person.y + bobAmount;
        
        let headColor = '#555';
        let bodyColor = '#444';
        
        if (gameState.audienceReaction === 'cheer' && timeSinceReaction < 4) {
            headColor = '#0f0';
            bodyColor = '#0a0';
            const armWave = Math.sin(time * 8 + idx * 0.5) * 4;
            
            ctx.fillStyle = bodyColor;
            ctx.fillRect(person.x - 4, y - 5 + armWave, 2, 5);
            ctx.fillRect(person.x + 6, y - 5 + armWave, 2, 5);
        } else if (gameState.audienceReaction === 'boo' && timeSinceReaction < 4) {
            headColor = '#f00';
            bodyColor = '#a00';
            
            ctx.fillStyle = bodyColor;
            ctx.fillRect(person.x - 4, y + 2, 2, 4);
            ctx.fillRect(person.x + 6, y + 2, 2, 4);
        } else {
            ctx.fillStyle = bodyColor;
            ctx.fillRect(person.x - 3, y + 2, 2, 4);
            ctx.fillRect(person.x + 5, y + 2, 2, 4);
        }
        
        ctx.fillStyle = headColor;
        ctx.beginPath();
        ctx.arc(person.x + 2, y, 5, 0, Math.PI * 2);
        ctx.fill();
        
        ctx.fillStyle = bodyColor;
        ctx.fillRect(person.x - 1, y + 4, 6, 8);
    });
    
    if (gameState.audienceReaction === 'cheer' && timeSinceReaction < 4) {
        ctx.font = 'bold 20px Courier New';
        ctx.textAlign = 'center';
        
        const texts = ['YAY!', 'WOO!', 'YEAH!', '🎉', '👍', 'CLAP!'];
        const fadeIn = Math.min(timeSinceReaction * 2, 1);
        const fadeOut = timeSinceReaction > 3 ? (4 - timeSinceReaction) : 1;
        const alpha = fadeIn * fadeOut;
        
        for (let i = 0; i < 8; i++) {
            const x = 80 + i * 70 + Math.sin(time * 3 + i) * 10;
            const y = 370 + Math.sin(time * 4 + i * 0.7) * 5;
            ctx.fillStyle = `rgba(0, 255, 0, ${alpha * 0.9})`;
            ctx.fillText(texts[i % texts.length], x, y);
        }
        ctx.textAlign = 'left';
    } else if (gameState.audienceReaction === 'boo' && timeSinceReaction < 4) {
        ctx.font = 'bold 20px Courier New';
        ctx.textAlign = 'center';
        
        const texts = ['BOO!', 'AWW!', 'NAH!', '👎', 'NO!'];
        const fadeIn = Math.min(timeSinceReaction * 2, 1);
        const fadeOut = timeSinceReaction > 3 ? (4 - timeSinceReaction) : 1;
        const alpha = fadeIn * fadeOut;
        
        for (let i = 0; i < 8; i++) {
            const x = 80 + i * 70 + Math.sin(time * 3 + i) * 10;
            const y = 370 + Math.sin(time * 4 + i * 0.7) * 5;
            ctx.fillStyle = `rgba(255, 0, 0, ${alpha * 0.9})`;
            ctx.fillText(texts[i % texts.length], x, y);
        }
        ctx.textAlign = 'left';
    }
}

function drawHost() {
    const h = host;
    const time = Date.now() / 1000;
    
    if (gameState.phase === 'walkToMonty') {
        const pulse = Math.sin(time * 3) * 0.5 + 0.5;
        const glowIntensity = 0.3 + pulse * 0.4;
        
        ctx.shadowBlur = 30;
        ctx.shadowColor = `rgba(0, 255, 255, ${glowIntensity})`;
        
        ctx.fillStyle = `rgba(0, 255, 255, ${glowIntensity * 0.3})`;
        ctx.fillRect(h.x - 15, h.y, 30, 40);
        
        ctx.fillStyle = `rgba(0, 255, 255, ${glowIntensity})`;
        ctx.fillRect(h.x - 10, h.y + 15, 20, 25);
    } else {
        ctx.shadowBlur = 0;
        ctx.fillStyle = '#000';
        ctx.fillRect(h.x - 10, h.y + 15, 20, 25);
    }
    
    if (gameState.phase === 'walkToMonty') {
        const pulse = Math.sin(time * 3) * 0.5 + 0.5;
        ctx.shadowColor = `rgba(255, 204, 153, ${0.5 + pulse * 0.5})`;
        ctx.shadowBlur = 15;
    }
    
    ctx.fillStyle = '#ffcc99';
    ctx.beginPath();
    ctx.arc(h.x, h.y + 10, 8, 0, Math.PI * 2);
    ctx.fill();
    
    ctx.shadowBlur = 0;
    
    if (gameState.phase === 'walkToMonty') {
        const pulse = Math.sin(time * 3) * 0.5 + 0.5;
        ctx.fillStyle = `rgba(0, 255, 255, ${0.5 + pulse * 0.5})`;
    } else {
        ctx.fillStyle = '#000';
    }
    ctx.fillRect(h.x - 10, h.y, 20, 5);
    ctx.fillRect(h.x - 7, h.y - 8, 14, 8);
    
    ctx.fillStyle = '#f00';
    ctx.fillRect(h.x - 6, h.y + 18, 12, 4);
    
    ctx.strokeStyle = '#888';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(h.x + 8, h.y + 25);
    ctx.lineTo(h.x + 15, h.y + 20);
    ctx.stroke();
    ctx.fillStyle = '#333';
    ctx.beginPath();
    ctx.arc(h.x + 15, h.y + 20, 3, 0, Math.PI * 2);
    ctx.fill();
    
    if (gameState.phase === 'walkToMonty') {
        const bounce = Math.sin(time * 4) * 3;
        ctx.fillStyle = '#0ff';
        ctx.font = 'bold 24px Courier New';
        ctx.textAlign = 'center';
        ctx.fillText('!', h.x, h.y - 18 + bounce);
        ctx.textAlign = 'left';
    }
}

function drawDoors() {
    doors.forEach((door, index) => {
        const isNear = getNearestDoor() === index;
        const isRevealed = gameState.revealedDoor === index;
        const isSelected = gameState.selectedDoor === index;
        const isPrize = gameState.prizeDoor === index;
        const showPrize = (gameState.phase === 'won' || gameState.phase === 'lost' || gameState.phase === 'questionTime') && isPrize;
        const showEmpty = isRevealed || (gameState.phase === 'lost' && !isPrize);
        
        if (showEmpty && !showPrize) {
            ctx.fillStyle = '#333';
            ctx.fillRect(door.x - 40, door.y, 80, 140);
            ctx.strokeStyle = '#666';
            ctx.lineWidth = 3;
            ctx.strokeRect(door.x - 40, door.y, 80, 140);
            
            ctx.strokeStyle = '#f00';
            ctx.lineWidth = 4;
            ctx.beginPath();
            ctx.moveTo(door.x - 20, door.y + 50);
            ctx.lineTo(door.x + 20, door.y + 90);
            ctx.stroke();
            ctx.beginPath();
            ctx.moveTo(door.x + 20, door.y + 50);
            ctx.lineTo(door.x - 20, door.y + 90);
            ctx.stroke();
        } else if (showPrize) {
            ctx.fillStyle = '#ffd700';
            ctx.fillRect(door.x - 40, door.y, 80, 140);
            ctx.strokeStyle = '#ff0';
            ctx.lineWidth = 3;
            ctx.strokeRect(door.x - 40, door.y, 80, 140);
            
            ctx.fillStyle = '#ff0';
            ctx.font = '40px Courier New';
            ctx.textAlign = 'center';
            ctx.fillText('🏆', door.x, door.y + 95);
            ctx.textAlign = 'left';
        } else {
            const doorColor = isNear ? '#8B4513' : '#654321';
            ctx.fillStyle = doorColor;
            ctx.fillRect(door.x - 40, door.y, 80, 140);
            ctx.strokeStyle = isNear ? '#0ff' : '#0f0';
            ctx.lineWidth = isNear ? 3 : 2;
            ctx.strokeRect(door.x - 40, door.y, 80, 140);
            
            ctx.strokeStyle = '#000';
            ctx.lineWidth = 2;
            ctx.strokeRect(door.x - 30, door.y + 10, 25, 50);
            ctx.strokeRect(door.x + 5, door.y + 10, 25, 50);
            ctx.strokeRect(door.x - 30, door.y + 70, 25, 50);
            ctx.strokeRect(door.x + 5, door.y + 70, 25, 50);
            
            ctx.fillStyle = '#ffd700';
            ctx.beginPath();
            ctx.arc(door.x + 25, door.y + 90, 5, 0, Math.PI * 2);
            ctx.fill();
        }
        
        ctx.fillStyle = '#ff0';
        ctx.font = 'bold 16px Courier New';
        ctx.textAlign = 'center';
        ctx.fillText(door.label, door.x, door.y + 160);
        
        if (isSelected && gameState.phase !== 'initial') {
            ctx.fillStyle = '#0ff';
            ctx.font = '20px Courier New';
            ctx.fillText('★', door.x, door.y - 10);
        }
    });
    ctx.textAlign = 'left';
}

function drawPlayer() {
    const p = gameState.player;
    
    ctx.fillStyle = 'rgba(0, 0, 0, 0.3)';
    ctx.beginPath();
    ctx.ellipse(p.x + 10, p.y + 30, 8, 3, 0, 0, Math.PI * 2);
    ctx.fill();
    
    ctx.fillStyle = '#00f';
    ctx.fillRect(p.x + 5, p.y + 10, 10, 15);
    
    ctx.fillStyle = '#ffcc99';
    ctx.beginPath();
    ctx.arc(p.x + 10, p.y + 7, 5, 0, Math.PI * 2);
    ctx.fill();
    
    ctx.fillStyle = '#ffd700';
    ctx.fillRect(p.x + 7, p.y + 2, 6, 3);
    ctx.fillRect(p.x + 9, p.y, 2, 2);
    
    ctx.fillStyle = '#000';
    ctx.fillRect(p.x + 6, p.y + 25, 3, 5);
    ctx.fillRect(p.x + 11, p.y + 25, 3, 5);
}

function gameLoop() {
    if (gameState.phase !== 'questionTime' && !gameState.showPuzzle) {
        movePlayer();
    }
    
    drawBackground();
    drawMorseVisual();
    drawAudience();
    drawHost();
    drawDoors();
    drawPlayer();
    
    requestAnimationFrame(gameLoop);
}

gameLoop();