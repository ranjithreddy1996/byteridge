const config = require('config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('_helpers/db');
const User = db.User;

module.exports = {
    authenticate,
    getAll,
    getById,
    create,
    update,
    delete: _delete,
    logout: _logout,
    audit: audit
};

async function audit(userParam) {
    const user = await User.findOne({ username: userParam.username });
    if (user.role == "AUDITOR") {
        const result = await User.find({ role: "USER" }, "username logoutTime loginTime")
        return result
    } else {
        return ("No permission")
    }

}
async function _logout({ username }) {
    let logoutTimeData = Date.now()
    const filter = { username: username };
    const update = { $push: { logoutTime: { logouttime: logoutTimeData } } };
    await User.updateOne(filter, update);
}
async function authenticate({ username, password, clientIP }) {
    const user = await User.findOne({ username });
    if (user && bcrypt.compareSync(password, user.hash)) {
        const { hash, ...userWithoutHash } = user.toObject();
        const token = jwt.sign({ sub: user.id, role: user.role }, config.secret);
        const filter = { username: username };
        const update = { $push: { loginTime: { clientIp: clientIP } } };
        await User.updateOne(filter, update);
        return {
            ...userWithoutHash,
            token
        };
    }
}

async function getAll() {
    return await User.find().select('-hash');
}

async function getById(id) {
    return await User.findById(id).select('-hash');
}

async function create(userParam) {

    // role required
    if (!userParam.role) {
        throw "role is required"
    }

    // validate
    if (await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    const user = new User(userParam);

    // hash password
    if (userParam.password) {
        user.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // save user
    await user.save();
}

async function update(id, userParam) {
    const user = await User.findById(id);

    // validate
    if (!user) throw 'User not found';
    if (user.username !== userParam.username && await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    // hash password if it was entered
    if (userParam.password) {
        userParam.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // copy userParam properties to user
    Object.assign(user, userParam);

    await user.save();
}

async function _delete(id) {
    await User.findByIdAndRemove(id);
}