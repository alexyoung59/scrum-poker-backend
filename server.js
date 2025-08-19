// server.js - Production-ready server
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: [
      "https://www.planwithpoker.us",
      "https://planwithpoker.us",
      "https://scrum-poker-frontend-chi.vercel.app"
    ],
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false // Allow Socket.io
}));

// CORS middleware
app.use(cors({
  origin: [
    "https://www.planwithpoker.us",
    "https://planwithpoker.us", 
    "https://scrum-poker-frontend-chi.vercel.app", // Current Vercel URL
    "http://localhost:3000" // For development
  ],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' ? 100 : 1000,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api', limiter);

// Health check endpoint (important for Railway)
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Plan With Poker API', 
    version: '1.0.0',
    status: 'Running'
  });
});

// MongoDB connection with retry logic
const connectDB = async () => {
  try {
    if (process.env.MONGODB_URI) {
      await mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
      console.log('✅ MongoDB connected successfully');
    } else {
      console.log('⚠️ MongoDB URI not provided - running without database');
    }
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    setTimeout(connectDB, 5000);
  }
};

connectDB();

// ===== MONGOOSE SCHEMAS =====

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

const User = mongoose.model('User', userSchema);

const roomSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  hostId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  participants: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    role: { type: String, enum: ['participant', 'observer'], default: 'participant' },
    joinedAt: { type: Date, default: Date.now }
  }],
  isActive: { type: Boolean, default: true },
  inviteCode: { type: String, unique: true },
  maxParticipants: { type: Number, default: 30 },
  createdAt: { type: Date, default: Date.now }
});

const Room = mongoose.model('Room', roomSchema);

const sessionSchema = new mongoose.Schema({
  roomId: { type: mongoose.Schema.Types.ObjectId, ref: 'Room', required: true },
  topic: { type: String, required: true },
  topicLink: { type: String },
  startTime: { type: Date, default: Date.now },
  endTime: { type: Date },
  finalVote: { type: String },
  consensus: { type: Boolean },
  isActive: { type: Boolean, default: true },
  votes: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    vote: { type: String },
    timestamp: { type: Date, default: Date.now }
  }]
});

const Session = mongoose.model('Session', sessionSchema);

// ===== MIDDLEWARE =====

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Validation middleware
const validateInput = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map(validation => validation.run(req)));
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }
    next();
  };
};

// ===== UTILITY FUNCTIONS =====

const generateInviteCode = () => {
  return Math.random().toString(36).substring(2, 8).toUpperCase();
};

// ===== API ROUTES =====

// Auth Routes
app.post('/api/auth/register', 
  validateInput([
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
    body('name').trim().isLength({ min: 2, max: 50 })
  ]),
  async (req, res) => {
    try {
      const { email, password, name } = req.body;

      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
      }

      const user = new User({ email, password, name });
      await user.save();

      const token = jwt.sign(
        { id: user._id, email: user.email, name: user.name },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.status(201).json({
        token,
        user: { id: user._id, email: user.email, name: user.name }
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.post('/api/auth/login',
  validateInput([
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
  ]),
  async (req, res) => {
    try {
      const { email, password } = req.body;

      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }

      user.lastLogin = new Date();
      await user.save();

      const token = jwt.sign(
        { id: user._id, email: user.email, name: user.name },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        token,
        user: { id: user._id, email: user.email, name: user.name }
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Room Routes
app.get('/api/rooms', authenticateToken, async (req, res) => {
  try {
    const rooms = await Room.find({
      $or: [
        { hostId: req.user.id },
        { 'participants.userId': req.user.id }
      ]
    })
    .populate('hostId', 'name email')
    .populate('participants.userId', 'name email')
    .sort({ createdAt: -1 });

    res.json(rooms);
  } catch (error) {
    console.error('Get rooms error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/rooms', 
  authenticateToken,
  validateInput([
    body('name').trim().isLength({ min: 3, max: 100 }),
    body('description').optional().trim().isLength({ max: 500 })
  ]),
  async (req, res) => {
    try {
      const { name, description } = req.body;
      
      const room = new Room({
        name,
        description,
        hostId: req.user.id,
        participants: [{ userId: req.user.id, role: 'participant' }],
        inviteCode: generateInviteCode()
      });

      await room.save();
      await room.populate('hostId', 'name email');
      await room.populate('participants.userId', 'name email');

      res.status(201).json(room);
    } catch (error) {
      console.error('Create room error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Add this route after the POST /api/rooms route
app.get('/api/rooms/:id', authenticateToken, async (req, res) => {
  try {
    const room = await Room.findById(req.params.id)
      .populate('hostId', 'name email')
      .populate('participants.userId', 'name email');

    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }

    // Check if user is participant or host
    const isParticipant = room.participants.some(p => p.userId._id.toString() === req.user.id);
    const isHost = room.hostId._id.toString() === req.user.id;

    if (!isParticipant && !isHost) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(room);
  } catch (error) {
    console.error('Get room error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Also add the join room route
app.post('/api/rooms/:id/join', authenticateToken, async (req, res) => {
  try {
    const { role = 'participant' } = req.body;
    const room = await Room.findById(req.params.id);

    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }

    // Check if room is full
    if (room.participants.length >= room.maxParticipants) {
      return res.status(400).json({ error: 'Room is full' });
    }

    // Check if user is already in room
    const isAlreadyParticipant = room.participants.some(p => p.userId.toString() === req.user.id);
    if (isAlreadyParticipant) {
      return res.status(400).json({ error: 'Already in room' });
    }

    // Add user to room
    room.participants.push({ userId: req.user.id, role });
    await room.save();

    // Populate the room data
    await room.populate('hostId', 'name email');
    await room.populate('participants.userId', 'name email');

    res.json({ message: 'Joined room successfully', room });
  } catch (error) {
    console.error('Join room error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Session Routes - Replace the validation part
app.post('/api/sessions', 
  authenticateToken,
  validateInput([
    body('roomId').isMongoId().withMessage('Invalid room ID'),
    body('topic').trim().isLength({ min: 1, max: 200 }).withMessage('Topic must be 1-200 characters'),
    body('topicLink').optional().custom((value) => {
      if (!value || value.trim() === '') return true; // Allow empty
      try {
        new URL(value);
        return true;
      } catch {
        throw new Error('Invalid URL format');
      }
    })
  ]),
  async (req, res) => {
    try {
      const { roomId, topic, topicLink } = req.body;

      // Verify user is in room
      const room = await Room.findById(roomId);
      if (!room) {
        return res.status(404).json({ error: 'Room not found' });
      }

      const isParticipant = room.participants.some(p => p.userId.toString() === req.user.id);
      const isHost = room.hostId.toString() === req.user.id;
      
      if (!isParticipant && !isHost) {
        return res.status(403).json({ error: 'Access denied' });
      }

      // End any active session in this room
      await Session.updateMany(
        { roomId, isActive: true }, 
        { isActive: false, endTime: new Date() }
      );

      // Create new session - handle empty topicLink
      const sessionData = { 
        roomId, 
        topic: topic.trim()
      };
      
      if (topicLink && topicLink.trim()) {
        sessionData.topicLink = topicLink.trim();
      }
      
      const session = new Session(sessionData);
      await session.save();

      console.log('Session created:', session); // Debug log

      // Emit to room that new session started
      io.to(roomId).emit('session_started', session);

      res.status(201).json(session);
    } catch (error) {
      console.error('Create session error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.post('/api/sessions/:id/vote', 
  authenticateToken,
  validateInput([
    body('vote').notEmpty().withMessage('Vote is required')
  ]),
  async (req, res) => {
    try {
      const { vote } = req.body;
      const session = await Session.findById(req.params.id);

      if (!session || !session.isActive) {
        return res.status(404).json({ error: 'Session not found or inactive' });
      }

      // Verify user is in room
      const room = await Room.findById(session.roomId);
      const participant = room.participants.find(p => p.userId.toString() === req.user.id);
      
      if (!participant || participant.role !== 'participant') {
        return res.status(403).json({ error: 'Only participants can vote' });
      }

      // Update or add vote
      const existingVoteIndex = session.votes.findIndex(v => v.userId.toString() === req.user.id);
      
      if (existingVoteIndex >= 0) {
        session.votes[existingVoteIndex].vote = vote;
        session.votes[existingVoteIndex].timestamp = new Date();
      } else {
        session.votes.push({ userId: req.user.id, vote });
      }

      await session.save();

      // Emit vote update to room
      io.to(session.roomId.toString()).emit('vote_updated', {
        sessionId: session._id,
        userId: req.user.id,
        hasVoted: true
      });

      res.json({ message: 'Vote recorded' });
    } catch (error) {
      console.error('Vote error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.post('/api/sessions/:id/reveal', 
  authenticateToken,
  async (req, res) => {
    try {
      const session = await Session.findById(req.params.id).populate('votes.userId', 'name email');

      if (!session || !session.isActive) {
        return res.status(404).json({ error: 'Session not found or inactive' });
      }

      // Verify user is host
      const room = await Room.findById(session.roomId);
      if (room.hostId.toString() !== req.user.id) {
        return res.status(403).json({ error: 'Only host can reveal votes' });
      }

      // Calculate stats
      const numericVotes = session.votes
        .map(v => v.vote)
        .filter(vote => !isNaN(vote) && vote !== '?' && vote !== '☕')
        .map(Number);

      const average = numericVotes.length > 0 
        ? (numericVotes.reduce((sum, vote) => sum + vote, 0) / numericVotes.length).toFixed(1)
        : null;

      const voteDistribution = {};
      session.votes.forEach(v => {
        voteDistribution[v.vote] = (voteDistribution[v.vote] || 0) + 1;
      });

      const consensus = Object.keys(voteDistribution).length === 1;
      
      // Update session
      session.finalVote = average ? average.toString() : 'No numeric votes';
      session.consensus = consensus;
      session.endTime = new Date();
      session.isActive = false;
      
      await session.save();

      const stats = { average, voteDistribution, consensus };

      // Emit reveal to room
      io.to(session.roomId.toString()).emit('votes_revealed', {
        sessionId: session._id,
        votes: session.votes,
        stats
      });

      res.json({ session, stats });
    } catch (error) {
      console.error('Reveal votes error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// ===== SOCKET.IO =====

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  
  if (!token) {
    return next(new Error('Authentication error'));
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return next(new Error('Authentication error'));
    socket.user = user;
    next();
  });
});

io.on('connection', (socket) => {
  console.log(`User ${socket.user.name} connected`);

  socket.on('join_room', (roomId) => {
    socket.join(roomId);
    socket.roomId = roomId;
    socket.to(roomId).emit('user_connected', { user: socket.user });
  });

  socket.on('disconnect', () => {
    if (socket.roomId) {
      socket.to(socket.roomId).emit('user_disconnected', { user: socket.user });
    }
  });
});

// ===== ERROR HANDLING =====

app.use((err, req, res, next) => {
  console.error('Error:', err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ===== START SERVER =====

const PORT = process.env.PORT || 5000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Environment: ${process.env.NODE_ENV || 'development'}`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    if (mongoose.connection.readyState === 1) {
      mongoose.connection.close();
    }
    process.exit(0);
  });
});

module.exports = { app, server, io };