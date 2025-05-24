const mongoose = require('mongoose');

const SystemSettingsSchema = new mongoose.Schema({
  maintenanceMode: { type: Boolean, default: false },
  cpuThrottle: { type: Number, default: 0, min: 0, max: 100 },
  systemStatus: { type: String, enum: ['online', 'shutting_down', 'offline'], default: 'online' }
}, { timestamps: true });

module.exports = mongoose.model('SystemSettings', SystemSettingsSchema);

const systemSettingsSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User' },
  twoFASecret: String,
  temp2FASecret: String,
  // ... other existing fields
});
