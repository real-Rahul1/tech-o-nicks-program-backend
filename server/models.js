const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
  title:       { type: String, required: true, trim: true },
  description: { type: String, required: true },
  speaker:     { type: String, required: true },
  date:        { type: Date,   required: true },
  time:        { type: String, required: true },
  duration:    { type: Number, required: true },
  venue:       { type: String, required: true },
  meetLink:    { type: String },
  image:       { type: String }, // base64 data URI or image URL for the session banner
  tags:        [{ type: String }],
  maxCapacity: { type: Number, default: 100 },
  isActive:    { type: Boolean, default: true },
  createdAt:   { type: Date, default: Date.now }
});

const registrationSchema = new mongoose.Schema({
  sessionId:          { type: mongoose.Schema.Types.ObjectId, ref: 'Session', required: true },
  fullName:           { type: String, required: true, trim: true },
  email:              { type: String, required: true, trim: true, lowercase: true },
  phone:              { type: String, required: true },
  college:            { type: String, required: true },
  branch:             { type: String, required: true },
  year:               { type: String, required: true },
  googleAccountEmail: { type: String, required: false, trim: true, lowercase: true },
  experience:         { type: String, enum: ['beginner', 'intermediate', 'advanced'], required: true },
  motivation:         { type: String },
  registeredAt:       { type: Date, default: Date.now }
});

registrationSchema.index({ email: 1, sessionId: 1 }, { unique: true });

// NEW: Community member schema
const communityMemberSchema = new mongoose.Schema({
  fullName:           { type: String, required: true, trim: true },
  email:              { type: String, required: true, trim: true, lowercase: true, unique: true },
  passwordHash:       { type: String, required: true },
  rollNumber:         { type: String, required: true, trim: true, uppercase: true, unique: true },
  phone:              { type: String, required: true },
  college:            { type: String, required: true },
  branch:             { type: String, required: true },
  year:               { type: String, required: true },
  interests:          [{ type: String }],
  experience:         { type: String, enum: ['beginner', 'intermediate', 'advanced'], required: true },
  whyJoin:            { type: String },
  joinedAt:           { type: Date, default: Date.now }
});

module.exports = {
  Session:         mongoose.model('Session', sessionSchema),
  Registration:    mongoose.model('Registration', registrationSchema),
  CommunityMember: mongoose.model('CommunityMember', communityMemberSchema)
};