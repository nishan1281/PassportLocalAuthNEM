const mongoose = require('mongoose');
const userSchema = mongoose.Schema({

    username: {
        type: String,
        require: true,
        unique: true,
    },

    password: {
        type: String,
        require: true,
    }
})

//creating model
const User = mongoose.model("User", userSchema);
module.exports = User;