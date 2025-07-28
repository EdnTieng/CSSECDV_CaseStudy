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
    role: {
        type: String,
        enum: ['Admin', 'manager', 'user'],
        required: true,
        default: 'user'
    }
});

userSchema.methods.comparePassword = function(password) {
    return this.password === password;
};

const User = mongoose.model('User', userSchema);

module.exports = User;