// server.js - Production-ready server
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const mongoose = require('mongoose');
const cron = require('node-cron');
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

const roomSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  hostName: { type: String, required: true },
  hostAnonymousId: { type: String, required: true },
  hostSocketId: { type: String },
  participants: [{
    name: { type: String, required: true },
    socketId: { type: String },
    anonymousId: { type: String, required: true },
    role: { type: String, enum: ['participant', 'observer'], default: 'participant' },
    joinedAt: { type: Date, default: Date.now }
  }],
  isActive: { type: Boolean, default: true },
  inviteCode: { type: String, unique: true },
  maxParticipants: { type: Number, default: 30 },
  createdAt: { type: Date, default: Date.now },
  lastActivity: { type: Date, default: Date.now }
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
    participantName: { type: String, required: true },
    anonymousId: { type: String, required: true },
    vote: { type: String },
    timestamp: { type: Date, default: Date.now }
  }]
});

const Session = mongoose.model('Session', sessionSchema);

// ===== MIDDLEWARE =====

// Generate or retrieve anonymous ID from request
const getAnonymousId = (req, res, next) => {
  req.anonymousId = req.headers['x-anonymous-id'] || generateAnonymousId();
  req.userName = req.headers['x-user-name'] || 'Anonymous';
  next();
};

const generateAnonymousId = () => {
  return `anon_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
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

// Room Routes
app.get('/api/rooms', getAnonymousId, async (req, res) => {
  try {
    // Get all active rooms or filter by user's anonymousId if requested
    const query = req.query.myRooms === 'true'
      ? {
          isActive: true,
          'participants.anonymousId': req.anonymousId
        }
      : { isActive: true };

    const rooms = await Room.find(query)
      .sort({ lastActivity: -1, createdAt: -1 });

    res.json(rooms);
  } catch (error) {
    console.error('Get rooms error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/rooms',
  getAnonymousId,
  validateInput([
    body('name').trim().isLength({ min: 3, max: 100 }),
    body('description').optional().trim().isLength({ max: 500 }),
    body('hostName').trim().isLength({ min: 2, max: 50 })
  ]),
  async (req, res) => {
    try {
      const { name, description, hostName } = req.body;

      const room = new Room({
        name,
        description,
        hostName: hostName || req.userName,
        hostAnonymousId: req.anonymousId,
        participants: [{
          name: hostName || req.userName,
          anonymousId: req.anonymousId,
          role: 'participant'
        }],
        inviteCode: generateInviteCode(),
        lastActivity: new Date()
      });

      await room.save();

      res.status(201).json(room);
    } catch (error) {
      console.error('Create room error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.get('/api/rooms/:id', getAnonymousId, async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);

    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }

    // Update lastActivity
    room.lastActivity = new Date();
    await room.save();

    res.json(room);
  } catch (error) {
    console.error('Get room error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/rooms/:id/join',
  getAnonymousId,
  validateInput([
    body('name').trim().isLength({ min: 2, max: 50 }),
    body('role').optional().isIn(['participant', 'observer'])
  ]),
  async (req, res) => {
    try {
      const { role = 'participant', name } = req.body;
      const room = await Room.findById(req.params.id);

      if (!room) {
        return res.status(404).json({ error: 'Room not found' });
      }

      if (room.participants.length >= room.maxParticipants) {
        return res.status(400).json({ error: 'Room is full' });
      }

      // Check if already in room by anonymousId
      const existingParticipant = room.participants.find(
        p => p.anonymousId === req.anonymousId
      );

      if (existingParticipant) {
        // Update existing participant (reconnection case)
        existingParticipant.name = name || existingParticipant.name;
        existingParticipant.role = role;
      } else {
        // Add new participant
        room.participants.push({
          name: name || req.userName,
          anonymousId: req.anonymousId,
          role
        });
      }

      room.lastActivity = new Date();
      await room.save();

      // Emit updated room data to all users in the room
      io.to(req.params.id).emit('room_updated', {
        roomId: req.params.id,
        room: room,
        participants: room.participants
      });

      res.json({ message: 'Joined room successfully', room });
    } catch (error) {
      console.error('Join room error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.post('/api/rooms/join-by-code',
  getAnonymousId,
  validateInput([
    body('inviteCode').trim().isLength({ min: 6, max: 6 }),
    body('name').trim().isLength({ min: 2, max: 50 }),
    body('role').optional().isIn(['participant', 'observer'])
  ]),
  async (req, res) => {
    try {
      const { inviteCode, role = 'participant', name } = req.body;

      const room = await Room.findOne({ inviteCode: inviteCode.toUpperCase() });

      if (!room) {
        return res.status(404).json({ error: 'Invalid invite code' });
      }

      if (room.participants.length >= room.maxParticipants) {
        return res.status(400).json({ error: 'Room is full' });
      }

      // Check if already in room by anonymousId
      const existingParticipant = room.participants.find(
        p => p.anonymousId === req.anonymousId
      );

      if (existingParticipant) {
        // Update existing participant (reconnection case)
        existingParticipant.name = name || existingParticipant.name;
        existingParticipant.role = role;
      } else {
        // Add new participant
        room.participants.push({
          name: name || req.userName,
          anonymousId: req.anonymousId,
          role
        });
      }

      room.lastActivity = new Date();
      await room.save();

      // Emit updated room data to all users in the room
      io.to(room._id.toString()).emit('room_updated', {
        roomId: room._id.toString(),
        room: room,
        participants: room.participants
      });

      res.json(room);
    } catch (error) {
      console.error('Join by code error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Session Routes
app.post('/api/sessions',
  getAnonymousId,
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

      const isParticipant = room.participants.some(p => p.anonymousId === req.anonymousId);

      if (!isParticipant) {
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

      // Update room activity
      room.lastActivity = new Date();
      await room.save();

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
  getAnonymousId,
  validateInput([
    body('vote').notEmpty().withMessage('Vote is required'),
    body('name').trim().isLength({ min: 2, max: 50 })
  ]),
  async (req, res) => {
    try {
      const { vote, name } = req.body;
      const session = await Session.findById(req.params.id);

      if (!session || !session.isActive) {
        return res.status(404).json({ error: 'Session not found or inactive' });
      }

      // Verify user is in room
      const room = await Room.findById(session.roomId);
      const participant = room.participants.find(p => p.anonymousId === req.anonymousId);

      if (!participant || participant.role !== 'participant') {
        return res.status(403).json({ error: 'Only participants can vote' });
      }

      // Update or add vote
      const existingVoteIndex = session.votes.findIndex(v => v.anonymousId === req.anonymousId);

      if (existingVoteIndex >= 0) {
        session.votes[existingVoteIndex].vote = vote;
        session.votes[existingVoteIndex].timestamp = new Date();
      } else {
        session.votes.push({
          participantName: name || participant.name,
          anonymousId: req.anonymousId,
          vote
        });
      }

      await session.save();

      // Update room activity
      room.lastActivity = new Date();
      await room.save();

      // Emit vote update to room
      io.to(session.roomId.toString()).emit('vote_updated', {
        sessionId: session._id,
        anonymousId: req.anonymousId,
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
  getAnonymousId,
  async (req, res) => {
    try {
      const session = await Session.findById(req.params.id);

      if (!session || !session.isActive) {
        return res.status(404).json({ error: 'Session not found or inactive' });
      }

      // Verify user is participant in the room
      const room = await Room.findById(session.roomId);
      const isParticipant = room.participants.some(p => p.anonymousId === req.anonymousId);

      if (!isParticipant) {
        return res.status(403).json({ error: 'Access denied' });
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

      // Update room activity
      room.lastActivity = new Date();
      await room.save();

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
  const userName = socket.handshake.auth.userName;
  const anonymousId = socket.handshake.auth.anonymousId;

  if (!userName || !anonymousId) {
    return next(new Error('Name and ID required'));
  }

  socket.userName = userName;
  socket.anonymousId = anonymousId;
  next();
});

io.on('connection', (socket) => {
  console.log(`User ${socket.userName} (${socket.anonymousId}) connected`);

  socket.on('join_room', async (roomId) => {
    console.log(`[JOIN_ROOM] ${socket.userName} joining room ${roomId}`);
    socket.join(roomId);
    socket.roomId = roomId;

    // Get updated room data and broadcast to all users in room
    try {
      const room = await Room.findById(roomId);

      if (room) {
        console.log(`[JOIN_ROOM] Room found: ${room.name}, participants: ${room.participants.length}`);

        // Update participant's socket ID for this connection
        const participant = room.participants.find(p => p.anonymousId === socket.anonymousId);

        if (participant) {
          console.log(`[JOIN_ROOM] Participant found, updating socketId`);
          participant.socketId = socket.id;
          room.lastActivity = new Date();
          await room.save();
        } else {
          console.log(`[JOIN_ROOM] WARNING: Participant ${socket.userName} (${socket.anonymousId}) not found in room!`);
        }

        // Send updated room data to all users in the room
        console.log(`[JOIN_ROOM] Broadcasting room_updated to ${room.participants.length} participants`);
        io.to(roomId).emit('room_updated', {
          roomId: roomId,
          room: room,
          participants: room.participants
        });

        // Also send user connected event
        socket.to(roomId).emit('user_connected', {
          user: {
            name: socket.userName,
            anonymousId: socket.anonymousId
          }
        });
        console.log(`[JOIN_ROOM] ${socket.userName} successfully joined room`);
      } else {
        console.log(`[JOIN_ROOM] ERROR: Room ${roomId} not found!`);
      }
    } catch (error) {
      console.error('Error updating room on join:', error);
    }
  });

  socket.on('leave_room', (roomId) => {
    socket.leave(roomId);
    socket.to(roomId).emit('user_disconnected', {
      user: {
        name: socket.userName,
        anonymousId: socket.anonymousId
      }
    });
  });

  socket.on('disconnect', async () => {
    console.log(`User ${socket.userName} disconnected`);

    if (socket.roomId) {
      try {
        // Clear socket ID from participant
        const room = await Room.findById(socket.roomId);
        if (room) {
          const participant = room.participants.find(p => p.anonymousId === socket.anonymousId);
          if (participant) {
            participant.socketId = null;
            await room.save();
          }
        }
      } catch (error) {
        console.error('Error updating room on disconnect:', error);
      }

      socket.to(socket.roomId).emit('user_disconnected', {
        user: {
          name: socket.userName,
          anonymousId: socket.anonymousId
        }
      });
    }
  });

  // Handle real-time voting
  socket.on('vote_cast', (data) => {
    console.log(`Vote cast by ${socket.userName}:`, data);
    socket.to(socket.roomId).emit('vote_updated', {
      sessionId: data.sessionId,
      anonymousId: socket.anonymousId,
      hasVoted: true
    });
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

// ===== ROOM CLEANUP JOB =====

// Room cleanup job - runs every hour
cron.schedule('0 * * * *', async () => {
  try {
    console.log('Running room cleanup job...');

    const expiryThreshold = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago

    const result = await Room.updateMany(
      { isActive: true, lastActivity: { $lt: expiryThreshold } },
      { isActive: false }
    );

    console.log(`Deactivated ${result.modifiedCount} inactive rooms`);

    // Also end active sessions in expired rooms
    if (result.modifiedCount > 0) {
      const expiredRooms = await Room.find({
        isActive: false,
        lastActivity: { $lt: expiryThreshold }
      }).select('_id');

      const roomIds = expiredRooms.map(r => r._id);

      await Session.updateMany(
        { roomId: { $in: roomIds }, isActive: true },
        { isActive: false, endTime: new Date() }
      );
    }
  } catch (error) {
    console.error('Room cleanup error:', error);
  }
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