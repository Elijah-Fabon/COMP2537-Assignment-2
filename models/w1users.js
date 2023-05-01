const mongoose = require('mongoose');
const usersSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  type: String
});


const usersModel = mongoose.model('w1users', usersSchema);

module.exports = usersModel;