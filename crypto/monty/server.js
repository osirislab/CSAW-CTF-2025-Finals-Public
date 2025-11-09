const express = require('express');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');
const WebSocket = require('ws');
const http = require('http');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ 
  server,
  maxPayload: 1024 * 10
});

// FLAG must be provided via environment variable
const FLAG = process.env.FLAG;
if (!FLAG) {
  console.error('ERROR: FLAG environment variable is not set!');
  process.exit(1);
}

const PORT = process.env.PORT || 3000;

const redisClient = createClient({
  socket: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379
  }
});

redisClient.connect().catch(console.error);
redisClient.on('error', (err) => console.error('Redis Client Error', err));
redisClient.on('connect', () => console.log('Redis connected'));

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
}));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(globalLimiter);

const sessionParser = session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET || 'change-me-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 3600000
  }
});

app.use(sessionParser);
app.use(express.json());
app.use(express.static('public'));

const answerLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: 'Too many attempts, please try again later.'
});

const gameSessions = new Map();

function initGameState(sessionId) {
  return {
    id: sessionId,
    wins: 0,
    losses: 0,
    switches: 0,
    stays: 0,
    currentPrizeDoor: Math.floor(Math.random() * 3),
    selectedDoor: null,
    revealedDoor: null,
    phase: 'initial',
    konamiProgress: 0,
    answeredQuestion: false,
    puzzleAnswer: null
  };
}

function encodeMorse(morse, wins, losses, switches, stays) {
  const shift = (wins * 3 + losses * 7 + switches * 5 + stays * 11) % 26;
  return morse.split('').map(char => {
    if (char >= 'a' && char <= 'z') {
      return String.fromCharCode((char.charCodeAt(0) - 97 + shift) % 26 + 97);
    }
    return char;
  }).join('');
}

function generateMorseAudio(state) {
  const flagText = FLAG;
  // Convert to lowercase for morse code (international standard - morse doesn't distinguish case)
  const encodedFlag = encodeMorse(flagText.toLowerCase(), state.wins, state.losses, state.switches, state.stays);
  
  // International Morse Code mapping (lowercase only)
  const morseMap = {
    'a': '.-', 'b': '-...', 'c': '-.-.', 'd': '-..', 'e': '.', 'f': '..-.',
    'g': '--.', 'h': '....', 'i': '..', 'j': '.---', 'k': '-.-', 'l': '.-..',
    'm': '--', 'n': '-.', 'o': '---', 'p': '.--.', 'q': '--.-', 'r': '.-.',
    's': '...', 't': '-', 'u': '..-', 'v': '...-', 'w': '.--', 'x': '-..-',
    'y': '-.--', 'z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', '{': '--.--', '}': '---.--', '_': '..--.-'
  };
  
  let morse = '';
  for (let char of encodedFlag) {
    if (morseMap[char]) {
      morse += morseMap[char] + ' ';
    } else if (char === ' ') {
      morse += '   '; // 7 units between words (3 spaces in morse notation)
    }
  }
  
  const dotDuration = 100;
  const dashDuration = 300;
  const symbolGap = 100;
  const letterGap = 300;
  
  const events = [];
  let time = 0;
  
  morse.split('').forEach(char => {
    if (char === '.') {
      events.push({ time, duration: dotDuration, type: 'dot' });
      time += dotDuration + symbolGap;
    } else if (char === '-') {
      events.push({ time, duration: dashDuration, type: 'dash' });
      time += dashDuration + symbolGap;
    } else if (char === ' ') {
      time += letterGap;
    }
  });
  
  return events;
}

const wsRateLimits = new Map();

wss.on('connection', (ws, request) => {
  const clientIP = request.headers['x-forwarded-for'] || request.socket.remoteAddress;
  
  if (!wsRateLimits.has(clientIP)) {
    wsRateLimits.set(clientIP, { count: 0, resetTime: Date.now() + 60000 });
  }

  sessionParser(request, {}, () => {
    const sessionId = request.session.id;
    
    if (!gameSessions.has(sessionId)) {
      gameSessions.set(sessionId, initGameState(sessionId));
    }
    
    ws.sessionId = sessionId;
    
    ws.send(JSON.stringify({
      type: 'init',
      state: getClientSafeState(sessionId)
    }));
    
    ws.on('message', (message) => {
      try {
        const limit = wsRateLimits.get(clientIP);
        if (Date.now() > limit.resetTime) {
          limit.count = 0;
          limit.resetTime = Date.now() + 60000;
        }
        
        if (limit.count++ > 100) {
          ws.close(1008, 'Rate limit exceeded');
          return;
        }
        
        if (message.length > 1024 * 10) {
          ws.close(1009, 'Message too large');
          return;
        }
        
        const data = JSON.parse(message);
        
        const validActions = ['selectDoor', 'submitAnswer', 'konamiKey', 'talkToMonty', 'puzzleAnswer'];
        if (!validActions.includes(data.action)) {
          return;
        }
        
        handleGameAction(ws, sessionId, data);
      } catch (error) {
        console.error('Invalid message:', error);
        ws.close(1003, 'Invalid data');
      }
    });
    
    ws.on('close', () => {
      setTimeout(() => {
        if (gameSessions.has(sessionId)) {
          gameSessions.delete(sessionId);
        }
      }, 300000);
    });
  });
});

setInterval(() => {
  const now = Date.now();
  for (const [ip, limit] of wsRateLimits.entries()) {
    if (now > limit.resetTime + 300000) {
      wsRateLimits.delete(ip);
    }
  }
}, 60000);

function getClientSafeState(sessionId) {
  const state = gameSessions.get(sessionId);
  return {
    wins: state.wins,
    losses: state.losses,
    switches: state.switches,
    stays: state.stays,
    selectedDoor: state.selectedDoor,
    revealedDoor: state.revealedDoor,
    phase: state.phase
  };
}

function handleGameAction(ws, sessionId, data) {
  const state = gameSessions.get(sessionId);
  
  switch (data.action) {
    case 'selectDoor':
      if (state.phase === 'initial') {
        state.selectedDoor = data.door;
        state.phase = 'firstChoice';
        
        setTimeout(() => {
          const doorsToReveal = [0, 1, 2].filter(d => 
            d !== state.selectedDoor && d !== state.currentPrizeDoor
          );
          state.revealedDoor = doorsToReveal[Math.floor(Math.random() * doorsToReveal.length)];
          state.phase = 'finalChoice';
          
          ws.send(JSON.stringify({
            type: 'update',
            state: getClientSafeState(sessionId),
            message: 'doorRevealed'
          }));
        }, 2000);
        
        ws.send(JSON.stringify({
          type: 'update',
          state: getClientSafeState(sessionId),
          message: 'firstSelected'
        }));
      } else if (state.phase === 'finalChoice') {
        const finalChoice = data.door;
        const switched = finalChoice !== state.selectedDoor;
        
        if (switched) {
          state.switches++;
        } else {
          state.stays++;
          state.phase = 'disqualified';
          ws.send(JSON.stringify({
            type: 'update',
            state: getClientSafeState(sessionId),
            message: 'stayedOnce',
            prizeDoor: state.currentPrizeDoor
          }));
          return;
        }
        
        state.selectedDoor = finalChoice;
        
        if (finalChoice === state.currentPrizeDoor) {
          state.wins++;
          state.phase = 'won';
          
          if (state.wins >= 3 && state.stays === 0) {
            state.phase = 'questionTime';
            ws.send(JSON.stringify({
              type: 'update',
              state: getClientSafeState(sessionId),
              message: 'askQuestion',
              prizeDoor: state.currentPrizeDoor
            }));
          } else {
            ws.send(JSON.stringify({
              type: 'update',
              state: getClientSafeState(sessionId),
              message: 'roundWon',
              prizeDoor: state.currentPrizeDoor
            }));
            setTimeout(() => resetRound(ws, sessionId), 3000);
          }
        } else {
          state.losses++;
          state.phase = 'lost';
          
          ws.send(JSON.stringify({
            type: 'update',
            state: getClientSafeState(sessionId),
            message: 'roundLost',
            prizeDoor: state.currentPrizeDoor
          }));
          
          setTimeout(() => resetRound(ws, sessionId), 3000);
        }
      }
      break;
      
    case 'submitAnswer':
      if (state.phase === 'questionTime' && data.answer === '42') {
        state.answeredQuestion = true;
        state.phase = 'waitingForCode';
        ws.send(JSON.stringify({
          type: 'update',
          state: getClientSafeState(sessionId),
          message: 'correctAnswer'
        }));
      } else if (state.phase === 'questionTime') {
        ws.send(JSON.stringify({
          type: 'update',
          state: getClientSafeState(sessionId),
          message: 'wrongAnswer'
        }));
      }
      break;
      
    case 'konamiKey':
      if (state.phase === 'waitingForCode') {
        const konamiCode = [38, 38, 40, 40, 37, 39, 37, 39, 66, 65];
        
        if (data.keyCode === konamiCode[state.konamiProgress]) {
          state.konamiProgress++;
          
          if (state.konamiProgress === konamiCode.length) {
            state.phase = 'playingMorse';
            const morseEvents = generateMorseAudio(state);
            
            ws.send(JSON.stringify({
              type: 'playMorse',
              events: morseEvents,
              message: 'codeAccepted'
            }));
            
            setTimeout(() => {
              state.phase = 'walkToMonty';
              ws.send(JSON.stringify({
                type: 'update',
                state: getClientSafeState(sessionId),
                message: 'morseComplete'
              }));
            }, morseEvents[morseEvents.length - 1].time + 2000);
          }
        } else {
          state.konamiProgress = 0;
        }
      }
      break;
      
    case 'talkToMonty':
      if (state.phase === 'walkToMonty') {
        state.phase = 'puzzle';
        ws.send(JSON.stringify({
          type: 'showPuzzle',
          puzzle: {
            question: "Three inhabitants stand before three doors (Red, Blue, Green). In this realm, Nobles always tell the truth, Hunters always lie, and Jesters alternate.\n\nAlex says: 'I am not the Jester.'\nBailey says: 'Exactly two of us are Nobles.'\nCasey says: 'The Blue door leads to the prize.'\n\nYou observe Bailey has spoken twice before (both were lies). Which door holds the prize?",
            options: [
              "The Red door - Casey must be lying",
              "The Blue door - Casey is telling the truth", 
              "The Green door - all three are deceiving you",
              "Cannot be determined from given information"
            ]
          },
          message: 'showPuzzle'
        }));
      }
      break;
      
    case 'puzzleAnswer':
      if (state.phase === 'puzzle') {
        if (data.answer === 2) {
          state.phase = 'puzzleSolved';
          ws.send(JSON.stringify({
            type: 'update',
            state: getClientSafeState(sessionId),
            message: 'puzzleCorrect'
          }));
        } else {
          state.phase = 'puzzleFailed';
          ws.send(JSON.stringify({
            type: 'update',
            state: getClientSafeState(sessionId),
            message: 'puzzleWrong'
          }));
        }
      }
      break;
  }
}

function resetRound(ws, sessionId) {
  const state = gameSessions.get(sessionId);
  state.currentPrizeDoor = Math.floor(Math.random() * 3);
  state.selectedDoor = null;
  state.revealedDoor = null;
  state.phase = 'initial';
  
  ws.send(JSON.stringify({
    type: 'update',
    state: getClientSafeState(sessionId),
    message: 'newRound'
  }));
}

app.post('/api/verify-flag', answerLimiter, [
  body('flag').isString().trim().isLength({ min: 1, max: 100 }).escape()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: 'Invalid input' });
  }
  
  const { flag } = req.body;
  
  if (flag === FLAG) {
    res.json({ success: true, message: 'Congratulations! Correct flag!' });
  } else {
    res.json({ success: false, message: 'Incorrect flag.' });
  }
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server...');
  server.close(() => {
    redisClient.quit();
    process.exit(0);
  });
});

server.listen(PORT, () => {
  console.log(`CTF Game server running on port ${PORT}`);
});