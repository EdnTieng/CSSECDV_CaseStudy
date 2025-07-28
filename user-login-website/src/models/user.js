const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    }
});

userSchema.methods.comparePassword = function(password) {
    // Logic to compare password (e.g., using bcrypt)
};

const User = mongoose.model('User', userSchema);

module.exports = User;